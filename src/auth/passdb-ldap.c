/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#if defined(PASSDB_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))

#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "db-ldap.h"

#include <ldap.h>

struct ldap_passdb_module {
	struct passdb_module module;

	struct ldap_connection *conn;
};

struct passdb_ldap_request {
	union {
		struct ldap_request ldap;
		struct ldap_request_search search;
		struct ldap_request_bind bind;
	} request;
	const char *dn;

	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} callback;

	unsigned int entries;
	bool require_password;
};

static void
ldap_query_save_result(struct ldap_connection *conn,
		       struct auth_request *auth_request,
		       struct ldap_request_search *ldap_request,
		       LDAPMessage *res)
{
	struct db_ldap_result_iterate_context *ldap_iter;
	const char *name, *const *values;

	ldap_iter = db_ldap_result_iterate_init(conn, ldap_request, res, FALSE);
	while (db_ldap_result_iterate_next(ldap_iter, &name, &values)) {
		if (values[0] == NULL) {
			auth_request_set_null_field(auth_request, name);
			continue;
		}
		if (values[1] != NULL) {
			e_warning(authdb_event(auth_request),
				  "Multiple values found for '%s', "
				  "using value '%s'", name, values[0]);
		}
		auth_request_set_field(auth_request, name, values[0],
				       conn->set.default_pass_scheme);
	}
	db_ldap_result_iterate_deinit(&ldap_iter);
}

static void
ldap_lookup_finish(struct auth_request *auth_request,
		   struct passdb_ldap_request *ldap_request,
		   LDAPMessage *res)
{
	enum passdb_result passdb_result;
	const char *password = NULL, *scheme;
	int ret;

	if (res == NULL) {
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else if (ldap_request->entries == 0) {
		passdb_result = PASSDB_RESULT_USER_UNKNOWN;
		auth_request_log_unknown_user(auth_request, AUTH_SUBSYS_DB);
	} else if (ldap_request->entries > 1) {
		e_error(authdb_event(auth_request),
			"pass_filter matched multiple objects, aborting");
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else if (auth_request->passdb_password == NULL &&
		   ldap_request->require_password &&
		   !auth_fields_exists(auth_request->extra_fields, "nopassword")) {
		passdb_result = auth_request_password_missing(auth_request);
	} else {
		/* passdb_password may change on the way,
		   so we'll need to strdup. */
		password = t_strdup(auth_request->passdb_password);
		passdb_result = PASSDB_RESULT_OK;
	}

	scheme = password_get_scheme(&password);
	/* auth_request_set_field() sets scheme */
	i_assert(password == NULL || scheme != NULL);

	if (auth_request->credentials_scheme != NULL) {
		passdb_handle_credentials(passdb_result, password, scheme,
			ldap_request->callback.lookup_credentials,
			auth_request);
	} else {
		if (password != NULL) {
			ret = auth_request_password_verify(auth_request,
					auth_request->mech_password,
					password, scheme, AUTH_SUBSYS_DB);
			passdb_result = ret > 0 ? PASSDB_RESULT_OK :
				PASSDB_RESULT_PASSWORD_MISMATCH;
		}

		ldap_request->callback.verify_plain(passdb_result,
						    auth_request);
	}
}

static void
ldap_lookup_pass_callback(struct ldap_connection *conn,
			  struct ldap_request *request, LDAPMessage *res)
{
	struct passdb_ldap_request *ldap_request =
		(struct passdb_ldap_request *)request;
        struct auth_request *auth_request = request->auth_request;

	if (res == NULL || ldap_msgtype(res) == LDAP_RES_SEARCH_RESULT) {
		ldap_lookup_finish(auth_request, ldap_request, res);
		auth_request_unref(&auth_request);
		return;
	}

	if (ldap_request->entries++ == 0) {
		/* first entry */
		ldap_query_save_result(conn, auth_request,
				       &ldap_request->request.search, res);
	}
}

static void
ldap_auth_bind_callback(struct ldap_connection *conn,
			struct ldap_request *ldap_request, LDAPMessage *res)
{
	struct passdb_ldap_request *passdb_ldap_request =
		(struct passdb_ldap_request *)ldap_request;
	struct auth_request *auth_request = ldap_request->auth_request;
	enum passdb_result passdb_result;
	int ret;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;

	if (res != NULL) {
		ret = ldap_result2error(conn->ld, res, 0);
		if (ret == LDAP_SUCCESS)
			passdb_result = PASSDB_RESULT_OK;
		else if (ret == LDAP_INVALID_CREDENTIALS) {
		  	auth_request_log_login_failure(auth_request,
				AUTH_SUBSYS_DB,
				AUTH_LOG_MSG_PASSWORD_MISMATCH" (for LDAP bind)");
			passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
		} else if (ret == LDAP_NO_SUCH_OBJECT) {
			passdb_result = PASSDB_RESULT_USER_UNKNOWN;
			auth_request_log_unknown_user(auth_request,
						      AUTH_SUBSYS_DB);
		} else {
			e_error(authdb_event(auth_request),
				"ldap_bind() failed: %s",
				ldap_err2string(ret));
		}
	}

	passdb_ldap_request->callback.
		verify_plain(passdb_result, auth_request);
        auth_request_unref(&auth_request);
}

static void ldap_auth_bind(struct ldap_connection *conn,
			   struct ldap_request_bind *brequest)
{
	struct passdb_ldap_request *passdb_ldap_request =
		(struct passdb_ldap_request *)brequest;
	struct auth_request *auth_request = brequest->request.auth_request;

	if (*auth_request->mech_password == '\0') {
		/* Assume that empty password fails. This is especially
		   important with Windows 2003 AD, which always returns success
		   with empty passwords. */
		e_info(authdb_event(auth_request),
		       "Login attempt with empty password");
		passdb_ldap_request->callback.
			verify_plain(PASSDB_RESULT_PASSWORD_MISMATCH,
				     auth_request);
		return;
	}

	brequest->request.callback = ldap_auth_bind_callback;
	db_ldap_request(conn, &brequest->request);
}

static void passdb_ldap_request_fail(struct passdb_ldap_request *request,
				     enum passdb_result passdb_result)
{
	struct auth_request *auth_request = request->request.ldap.auth_request;

	if (auth_request->credentials_scheme != NULL) {
		request->callback.lookup_credentials(passdb_result, NULL, 0,
						     auth_request);
	} else {
		request->callback.verify_plain(passdb_result, auth_request);
	}
	auth_request_unref(&auth_request);
}

static void
ldap_bind_lookup_dn_fail(struct auth_request *auth_request,
			 struct passdb_ldap_request *request,
			 LDAPMessage *res)
{
	enum passdb_result passdb_result;

	if (res == NULL)
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	else if (request->entries == 0) {
		passdb_result = PASSDB_RESULT_USER_UNKNOWN;
		auth_request_log_unknown_user(auth_request, AUTH_SUBSYS_DB);
	} else {
		i_assert(request->entries > 1);
		e_error(authdb_event(auth_request),
			"pass_filter matched multiple objects, aborting");
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	}

	passdb_ldap_request_fail(request, passdb_result);
}

static void ldap_bind_lookup_dn_callback(struct ldap_connection *conn,
					 struct ldap_request *ldap_request,
					 LDAPMessage *res)
{
	struct passdb_ldap_request *passdb_ldap_request =
		(struct passdb_ldap_request *)ldap_request;
	struct auth_request *auth_request = ldap_request->auth_request;
	struct passdb_ldap_request *brequest;
	char *dn;

	if (res != NULL && ldap_msgtype(res) == LDAP_RES_SEARCH_ENTRY) {
		if (passdb_ldap_request->entries++ > 0) {
			/* too many replies */
			return;
		}

		/* first entry */
		ldap_query_save_result(conn, auth_request,
				       &passdb_ldap_request->request.search, res);

		/* save dn */
		dn = ldap_get_dn(conn->ld, res);
		passdb_ldap_request->dn = p_strdup(auth_request->pool, dn);
		ldap_memfree(dn);
	} else if (res == NULL || passdb_ldap_request->entries != 1) {
		/* failure */
		ldap_bind_lookup_dn_fail(auth_request, passdb_ldap_request, res);
	} else if (auth_request->skip_password_check) {
		/* we've already verified that the password matched -
		   we just wanted to get any extra fields */
		passdb_ldap_request->callback.
			verify_plain(PASSDB_RESULT_OK, auth_request);
		auth_request_unref(&auth_request);
	} else {
		/* create a new bind request */
		brequest = p_new(auth_request->pool,
				 struct passdb_ldap_request, 1);
		brequest->dn = passdb_ldap_request->dn;
		brequest->callback = passdb_ldap_request->callback;
		brequest->request.bind.dn = brequest->dn;
		brequest->request.bind.request.type = LDAP_REQUEST_TYPE_BIND;
		brequest->request.bind.request.auth_request = auth_request;

		ldap_auth_bind(conn, &brequest->request.bind);
	}
}

static void ldap_lookup_pass(struct auth_request *auth_request,
			     struct passdb_ldap_request *request,
			     bool require_password)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct ldap_connection *conn = module->conn;
	struct ldap_request_search *srequest = &request->request.search;
	const char **attr_names = (const char **)conn->pass_attr_names;
	const char *error;
	string_t *str;

	request->require_password = require_password;
	srequest->request.type = LDAP_REQUEST_TYPE_SEARCH;

	str = t_str_new(512);
	if (auth_request_var_expand(str, conn->set.base, auth_request,
				    ldap_escape, &error) <= 0) {
		e_error(authdb_event(auth_request),
			"Failed to expand base=%s: %s", conn->set.base, error);
		passdb_ldap_request_fail(request, PASSDB_RESULT_INTERNAL_FAILURE);
		return;
	}
	srequest->base = p_strdup(auth_request->pool, str_c(str));

	str_truncate(str, 0);
	if (auth_request_var_expand(str, conn->set.pass_filter,
				    auth_request, ldap_escape, &error) <= 0) {
		e_error(authdb_event(auth_request),
			"Failed to expand pass_filter=%s: %s",
			conn->set.pass_filter, error);
		passdb_ldap_request_fail(request, PASSDB_RESULT_INTERNAL_FAILURE);
		return;
	}
	srequest->filter = p_strdup(auth_request->pool, str_c(str));
	srequest->attr_map = &conn->pass_attr_map;
	srequest->attributes = conn->pass_attr_names;

	e_debug(authdb_event(auth_request), "pass search: "
		"base=%s scope=%s filter=%s fields=%s",
		srequest->base, conn->set.scope,
		srequest->filter, attr_names == NULL ? "(all)" :
		t_strarray_join(attr_names, ","));

	srequest->request.callback = ldap_lookup_pass_callback;
	db_ldap_request(conn, &srequest->request);
}

static void ldap_bind_lookup_dn(struct auth_request *auth_request,
				struct passdb_ldap_request *request)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct ldap_connection *conn = module->conn;
	struct ldap_request_search *srequest = &request->request.search;
	const char *error;
	string_t *str;

	srequest->request.type = LDAP_REQUEST_TYPE_SEARCH;

	str = t_str_new(512);
	if (auth_request_var_expand(str, conn->set.base, auth_request,
				    ldap_escape, &error) <= 0) {
		e_error(authdb_event(auth_request),
			"Failed to expand base=%s: %s", conn->set.base, error);
		passdb_ldap_request_fail(request, PASSDB_RESULT_INTERNAL_FAILURE);
		return;
	}
	srequest->base = p_strdup(auth_request->pool, str_c(str));

	str_truncate(str, 0);
	if (auth_request_var_expand(str, conn->set.pass_filter,
				    auth_request, ldap_escape, &error) <= 0) {
		e_error(authdb_event(auth_request),
			"Failed to expand pass_filter=%s: %s",
			conn->set.pass_filter, error);
		passdb_ldap_request_fail(request, PASSDB_RESULT_INTERNAL_FAILURE);
		return;
	}
	srequest->filter = p_strdup(auth_request->pool, str_c(str));

	/* we don't need the attributes to perform authentication, but they
	   may contain some extra parameters. if a password is returned,
	   it's just ignored. */
	srequest->attr_map = &conn->pass_attr_map;
	srequest->attributes = conn->pass_attr_names;

	e_debug(authdb_event(auth_request),
		"bind search: base=%s filter=%s",
		srequest->base, srequest->filter);

	srequest->request.callback = ldap_bind_lookup_dn_callback;
        db_ldap_request(conn, &srequest->request);
}

static void
ldap_verify_plain_auth_bind_userdn(struct auth_request *auth_request,
				   struct passdb_ldap_request *request)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct ldap_connection *conn = module->conn;
	struct ldap_request_bind *brequest = &request->request.bind;
	string_t *dn;
	const char *error;

	brequest->request.type = LDAP_REQUEST_TYPE_BIND;

	dn = t_str_new(512);
	if (auth_request_var_expand(dn, conn->set.auth_bind_userdn,
				    auth_request, ldap_escape, &error) <= 0) {
		e_error(authdb_event(auth_request),
			"Failed to expand auth_bind_userdn=%s: %s",
			conn->set.auth_bind_userdn, error);
		passdb_ldap_request_fail(request, PASSDB_RESULT_INTERNAL_FAILURE);
		return;
	}

	brequest->dn = p_strdup(auth_request->pool, str_c(dn));
        ldap_auth_bind(conn, brequest);
}

static void
ldap_verify_plain(struct auth_request *request,
		  const char *password ATTR_UNUSED,
		  verify_plain_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct ldap_connection *conn = module->conn;
	struct passdb_ldap_request *ldap_request;

	/* reconnect if needed. this is also done by db_ldap_search(), but
	   with auth binds we'll have to do it ourself */
	if (db_ldap_connect(conn)< 0) {
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	ldap_request = p_new(request->pool, struct passdb_ldap_request, 1);
	ldap_request->callback.verify_plain = callback;

	auth_request_ref(request);
	ldap_request->request.ldap.auth_request = request;

	if (!conn->set.auth_bind)
		ldap_lookup_pass(request, ldap_request, TRUE);
	else if (conn->set.auth_bind_userdn == NULL)
		ldap_bind_lookup_dn(request, ldap_request);
	else
		ldap_verify_plain_auth_bind_userdn(request, ldap_request);
}

static void ldap_lookup_credentials(struct auth_request *request,
				    lookup_credentials_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct passdb_ldap_request *ldap_request;
	bool require_password;

	ldap_request = p_new(request->pool, struct passdb_ldap_request, 1);
	ldap_request->callback.lookup_credentials = callback;

	auth_request_ref(request);
	ldap_request->request.ldap.auth_request = request;

	/* with auth_bind=yes we don't necessarily have a password.
	   this will fail actual password credentials lookups, but it's fine
	   for passdb lookups done by lmtp/doveadm */
	require_password = !module->conn->set.auth_bind;
        ldap_lookup_pass(request, ldap_request, require_password);
}

static struct passdb_module *
passdb_ldap_preinit(pool_t pool, const char *args)
{
	struct ldap_passdb_module *module;
	struct ldap_connection *conn;

	module = p_new(pool, struct ldap_passdb_module, 1);
	module->conn = conn = db_ldap_init(args, FALSE);
	p_array_init(&conn->pass_attr_map, pool, 16);
	db_ldap_set_attrs(conn, conn->set.pass_attrs, &conn->pass_attr_names,
			  &conn->pass_attr_map,
			  conn->set.auth_bind ? "password" : NULL);
	module->module.blocking = conn->set.blocking;
	module->module.default_cache_key =
		auth_cache_parse_key(pool,
				     t_strconcat(conn->set.base,
						 conn->set.pass_attrs,
						 conn->set.pass_filter, NULL));
	module->module.default_pass_scheme = conn->set.default_pass_scheme;
	return &module->module;
}

static void passdb_ldap_init(struct passdb_module *_module)
{
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;

	if (!module->module.blocking || worker)
		db_ldap_connect_delayed(module->conn);
}

static void passdb_ldap_deinit(struct passdb_module *_module)
{
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;

	db_ldap_unref(&module->conn);
}

#ifndef PLUGIN_BUILD
struct passdb_module_interface passdb_ldap =
#else
struct passdb_module_interface passdb_ldap_plugin =
#endif
{
	"ldap",

	passdb_ldap_preinit,
	passdb_ldap_init,
	passdb_ldap_deinit,

	ldap_verify_plain,
	ldap_lookup_credentials,
	NULL
};
#else
struct passdb_module_interface passdb_ldap = {
	.name = "ldap"
};
#endif
