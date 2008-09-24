/* Copyright (c) 2003-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "passdb.h"

#ifdef PASSDB_LDAP

#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "db-ldap.h"

#include <ldap.h>
#include <stdlib.h>

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

	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} callback;
};

static LDAPMessage *
handle_request_get_entry(struct ldap_connection *conn,
			 struct auth_request *auth_request,
			 struct passdb_ldap_request *request, LDAPMessage *res)
{
	enum passdb_result passdb_result;
	LDAPMessage *entry;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;

	if (res != NULL) {
		/* LDAP search was successful */
		entry = ldap_first_entry(conn->ld, res);
		if (entry == NULL) {
			passdb_result = PASSDB_RESULT_USER_UNKNOWN;
			auth_request_log_info(auth_request, "ldap",
					      "unknown user");
		} else {
			if (ldap_next_entry(conn->ld, entry) == NULL) {
				/* success */
				return entry;
			}

			auth_request_log_error(auth_request, "ldap",
				"Multiple replies found for user");
		}
	}

	if (auth_request->credentials_scheme != NULL) {
		request->callback.lookup_credentials(passdb_result, NULL, 0,
						     auth_request);
	} else {
		request->callback.verify_plain(passdb_result, auth_request);
	}
	auth_request_unref(&auth_request);
	return NULL;
}

static void
ldap_query_save_result(struct ldap_connection *conn,
		       LDAPMessage *entry, struct auth_request *auth_request)
{
	struct db_ldap_result_iterate_context *ldap_iter;
	const char *name, *value;

	ldap_iter = db_ldap_result_iterate_init(conn, entry, auth_request,
						conn->pass_attr_map);
	while (db_ldap_result_iterate_next(ldap_iter, &name, &value)) {
		auth_request_set_field(auth_request, name, value,
				       conn->set.default_pass_scheme);
	}
}

static void
ldap_lookup_pass_callback(struct ldap_connection *conn,
			  struct ldap_request *request, LDAPMessage *res)
{
	struct passdb_ldap_request *ldap_request =
		(struct passdb_ldap_request *)request;
        struct auth_request *auth_request = request->auth_request;
	enum passdb_result passdb_result;
	LDAPMessage *entry;
	const char *password, *scheme;
	int ret;

	entry = handle_request_get_entry(conn, auth_request, ldap_request, res);
	if (entry == NULL)
		return;

	/* got first LDAP entry */
	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	password = NULL;

	ldap_query_save_result(conn, entry, auth_request);
	if (auth_request->passdb_password == NULL) {
		auth_request_log_error(auth_request, "ldap",
				       "No password in reply");
	} else if (ldap_next_entry(conn->ld, entry) != NULL) {
		auth_request_log_error(auth_request, "ldap",
			"pass_filter matched multiple objects, aborting");
	} else if (auth_request->passdb_password == NULL &&
		   !auth_request->no_password) {
		auth_request_log_info(auth_request, "ldap",
			"Empty password returned without nopassword");
		passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
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
					password, scheme, "ldap");
			passdb_result = ret > 0 ? PASSDB_RESULT_OK :
				PASSDB_RESULT_PASSWORD_MISMATCH;
		}

		ldap_request->callback.verify_plain(passdb_result,
						    auth_request);
	}
	auth_request_unref(&auth_request);
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
			auth_request_log_info(auth_request, "ldap",
					      "invalid credentials");
			passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
		} else {
			auth_request_log_error(auth_request, "ldap",
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
		auth_request_log_info(auth_request, "ldap",
				      "Login attempt with empty password");
		passdb_ldap_request->callback.
			verify_plain(PASSDB_RESULT_PASSWORD_MISMATCH,
				     auth_request);
		return;
	}

	brequest->request.callback = ldap_auth_bind_callback;
	db_ldap_request(conn, &brequest->request);
}

static void ldap_bind_lookup_dn_callback(struct ldap_connection *conn,
					 struct ldap_request *ldap_request,
					 LDAPMessage *res)
{
	struct passdb_ldap_request *passdb_ldap_request =
		(struct passdb_ldap_request *)ldap_request;
	struct ldap_request_bind *brequest;
	struct auth_request *auth_request = ldap_request->auth_request;
	LDAPMessage *entry;
	char *dn;

	entry = handle_request_get_entry(conn, auth_request,
					 passdb_ldap_request, res);
	if (entry == NULL)
		return;

	ldap_query_save_result(conn, entry, auth_request);

	/* convert search request to bind request */
	brequest = &passdb_ldap_request->request.bind;
	memset(brequest, 0, sizeof(*brequest));
	brequest->request.type = LDAP_REQUEST_TYPE_BIND;
	brequest->request.auth_request = auth_request;

	/* switch the handler to the authenticated bind handler */
	dn = ldap_get_dn(conn->ld, entry);
	brequest->dn = p_strdup(auth_request->pool, dn);
	ldap_memfree(dn);

	ldap_auth_bind(conn, brequest);
}

static void ldap_lookup_pass(struct auth_request *auth_request,
			     struct passdb_ldap_request *request)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct ldap_connection *conn = module->conn;
	struct ldap_request_search *srequest = &request->request.search;
	const struct var_expand_table *vars;
	const char **attr_names = (const char **)conn->pass_attr_names;
	string_t *str;

	srequest->request.type = LDAP_REQUEST_TYPE_SEARCH;
	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);

	str = t_str_new(512);
	var_expand(str, conn->set.base, vars);
	srequest->base = p_strdup(auth_request->pool, str_c(str));

	str_truncate(str, 0);
	var_expand(str, conn->set.pass_filter, vars);
	srequest->filter = p_strdup(auth_request->pool, str_c(str));
	srequest->attributes = conn->pass_attr_names;

	auth_request_log_debug(auth_request, "ldap", "pass search: "
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
	const struct var_expand_table *vars;
	string_t *str;

	srequest->request.type = LDAP_REQUEST_TYPE_SEARCH;
	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);

	str = t_str_new(512);
	var_expand(str, conn->set.base, vars);
	srequest->base = p_strdup(auth_request->pool, str_c(str));

	str_truncate(str, 0);
	var_expand(str, conn->set.pass_filter, vars);
	srequest->filter = p_strdup(auth_request->pool, str_c(str));

	/* we don't need the attributes to perform authentication, but they
	   may contain some extra parameters. if a password is returned,
	   it's just ignored. */
	srequest->attributes = conn->pass_attr_names;

	auth_request_log_debug(auth_request, "ldap",
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
        const struct var_expand_table *vars;
	string_t *dn;

	brequest->request.type = LDAP_REQUEST_TYPE_BIND;

	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);
	dn = t_str_new(512);
	var_expand(dn, conn->set.auth_bind_userdn, vars);

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
		ldap_lookup_pass(request, ldap_request);
	else if (conn->set.auth_bind_userdn == NULL)
		ldap_bind_lookup_dn(request, ldap_request);
	else
		ldap_verify_plain_auth_bind_userdn(request, ldap_request);
}

static void ldap_lookup_credentials(struct auth_request *request,
				    lookup_credentials_callback_t *callback)
{
	struct passdb_ldap_request *ldap_request;

	ldap_request = p_new(request->pool, struct passdb_ldap_request, 1);
	ldap_request->callback.lookup_credentials = callback;

	auth_request_ref(request);
	ldap_request->request.ldap.auth_request = request;

        ldap_lookup_pass(request, ldap_request);
}

static struct passdb_module *
passdb_ldap_preinit(struct auth_passdb *auth_passdb, const char *args)
{
	struct ldap_passdb_module *module;
	struct ldap_connection *conn;

	module = p_new(auth_passdb->auth->pool, struct ldap_passdb_module, 1);
	module->conn = conn = db_ldap_init(args);
	conn->pass_attr_map =
		hash_create(default_pool, conn->pool, 0, str_hash,
			    (hash_cmp_callback_t *)strcmp);

	db_ldap_set_attrs(conn, conn->set.pass_attrs, &conn->pass_attr_names,
			  conn->pass_attr_map,
			  conn->set.auth_bind ? "password" : NULL);
	module->module.cache_key =
		auth_cache_parse_key(auth_passdb->auth->pool,
				     t_strconcat(conn->set.base,
						 conn->set.pass_filter, NULL));
	module->module.default_pass_scheme = conn->set.default_pass_scheme;
	return &module->module;
}

static void passdb_ldap_init(struct passdb_module *_module,
			     const char *args ATTR_UNUSED)
{
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;

	(void)db_ldap_connect(module->conn);

	if (module->conn->set.auth_bind) {
		/* Credential lookups can't be done with authentication binds */
		_module->iface.lookup_credentials = NULL;
	}
}

static void passdb_ldap_deinit(struct passdb_module *_module)
{
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;

	db_ldap_unref(&module->conn);
}

struct passdb_module_interface passdb_ldap = {
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
	MEMBER(name) "ldap"
};
#endif
