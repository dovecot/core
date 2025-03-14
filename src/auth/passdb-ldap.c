/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))

#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "settings.h"
#include "auth-settings.h"
#include "db-ldap.h"

#include <ldap.h>

#define RAW_SETTINGS (SETTINGS_GET_FLAG_NO_CHECK | SETTINGS_GET_FLAG_NO_EXPAND)

struct ldap_passdb_module {
	struct passdb_module module;

	struct ldap_connection *conn;
	const char *const *attributes;
	const char *const *sensitive_attr_names;
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
	bool require_password:1;
	bool failed:1;
};

static int
ldap_query_save_result(struct ldap_connection *conn,
		       struct auth_request *auth_request,
		       struct ldap_request_search *ldap_request,
		       LDAPMessage *res)
{
	struct db_ldap_field_expand_context ctx = {
		.event = authdb_event(auth_request),
	};
	if (res != NULL) {
		ctx.fields = ldap_query_get_fields(auth_request->pool, conn,
						   ldap_request, res, FALSE);
	}

	const char *default_password_scheme =
		auth_request->passdb->set->default_password_scheme;

	return auth_request_set_passdb_fields_ex(auth_request, &ctx,
						 default_password_scheme,
						 db_ldap_field_expand_fn_table);
}

static void
ldap_lookup_finish(struct auth_request *auth_request,
		   struct passdb_ldap_request *ldap_request,
		   LDAPMessage *res)
{
	enum passdb_result passdb_result;
	const char *password = NULL, *scheme;

	if (res == NULL || ldap_request->failed) {
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else if (ldap_request->entries == 0) {
		passdb_result = PASSDB_RESULT_USER_UNKNOWN;
		auth_request_db_log_unknown_user(auth_request);
	} else if (ldap_request->entries > 1) {
		e_error(authdb_event(auth_request),
			"passdb_ldap_filter matched multiple objects, aborting");
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else if (auth_request->passdb_password == NULL &&
		   ldap_request->require_password &&
		   !auth_fields_exists(auth_request->fields.extra_fields, "nopassword")) {
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

	if (auth_request->wanted_credentials_scheme != NULL) {
		passdb_handle_credentials(passdb_result, password, scheme,
			ldap_request->callback.lookup_credentials,
			auth_request);
	} else {
		if (password != NULL) {
			passdb_result = auth_request_db_password_verify(
				auth_request, auth_request->mech_password,
				password, scheme);
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
		container_of(request, struct passdb_ldap_request, request.ldap);
        struct auth_request *auth_request = request->auth_request;

	if (res == NULL || ldap_msgtype(res) == LDAP_RES_SEARCH_RESULT) {
		ldap_lookup_finish(auth_request, ldap_request, res);
		auth_request_unref(&auth_request);
		return;
	}

	if (ldap_request->entries++ == 0) {
		/* first entry */
		if (ldap_query_save_result(conn, auth_request,
					   &ldap_request->request.search, res) < 0)
			ldap_request->failed = TRUE;
	}
}

static void
ldap_auth_bind_callback(struct ldap_connection *conn,
			struct ldap_request *ldap_request, LDAPMessage *res)
{
	struct passdb_ldap_request *passdb_ldap_request =
		container_of(ldap_request, struct passdb_ldap_request, request.ldap);
	struct auth_request *auth_request = ldap_request->auth_request;
	enum passdb_result passdb_result;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;

	if (res != NULL) {
		int result;
		int ret = ldap_parse_result(conn->ld, res, &result,
					    NULL, NULL, NULL, NULL, FALSE);
		if (ret == LDAP_SUCCESS)
			ret = result;
		if (ret == LDAP_SUCCESS)
			passdb_result = PASSDB_RESULT_OK;
		else if (ret == LDAP_INVALID_CREDENTIALS) {
			auth_request_db_log_login_failure(auth_request,
				AUTH_LOG_MSG_PASSWORD_MISMATCH" (for LDAP bind)");
			passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
		} else if (ret == LDAP_NO_SUCH_OBJECT) {
			passdb_result = PASSDB_RESULT_USER_UNKNOWN;
			auth_request_db_log_unknown_user(auth_request);
		} else {
			e_error(authdb_event(auth_request),
				"ldap_sasl_bind() failed: %s",
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
		container_of(brequest, struct passdb_ldap_request, request.bind);
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

	if (auth_request->wanted_credentials_scheme != NULL) {
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
		auth_request_db_log_unknown_user(auth_request);
	} else {
		i_assert(request->entries > 1);
		e_error(authdb_event(auth_request),
			"passdb_ldap_filter matched multiple objects, aborting");
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	}

	passdb_ldap_request_fail(request, passdb_result);
}

static void ldap_bind_lookup_dn_callback(struct ldap_connection *conn,
					 struct ldap_request *ldap_request,
					 LDAPMessage *res)
{
	struct passdb_ldap_request *passdb_ldap_request =
		container_of(ldap_request, struct passdb_ldap_request, request.ldap);
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
	} else if (auth_request->fields.skip_password_check) {
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
			     const struct ldap_pre_settings *ldap_set,
			     bool require_password)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		container_of(_module, struct ldap_passdb_module, module);
	struct ldap_connection *conn = module->conn;
	struct ldap_request_search *srequest = &request->request.search;

	request->require_password = require_password;
	srequest->request.type = LDAP_REQUEST_TYPE_SEARCH;
	srequest->base = p_strdup(auth_request->pool, ldap_set->ldap_base);
	srequest->filter = p_strdup(auth_request->pool,
				    ldap_set->passdb_ldap_filter);
	srequest->attributes = module->attributes;
	srequest->sensitive_attr_names = module->sensitive_attr_names;

	e_debug(authdb_event(auth_request), "pass search: "
		"base=%s scope=%s filter=%s fields=%s",
		srequest->base, conn->set->scope,
		srequest->filter,
		t_strarray_join(module->attributes, ","));

	srequest->request.callback = ldap_lookup_pass_callback;
	db_ldap_request(conn, &srequest->request);
}

static void ldap_bind_lookup_dn(struct auth_request *auth_request,
				struct passdb_ldap_request *request,
				const struct ldap_pre_settings *ldap_set)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		container_of(_module, struct ldap_passdb_module, module);
	struct ldap_connection *conn = module->conn;
	struct ldap_request_search *srequest = &request->request.search;

	srequest->request.type = LDAP_REQUEST_TYPE_SEARCH;
	srequest->base = p_strdup(auth_request->pool, ldap_set->ldap_base);
	srequest->filter = p_strdup(auth_request->pool,
				    ldap_set->passdb_ldap_filter);

	/* we don't need the attributes to perform authentication, but they
	   may contain some extra parameters. if a password is returned,
	   it's just ignored. */
	srequest->attributes = module->attributes;
	srequest->sensitive_attr_names = module->sensitive_attr_names;

	e_debug(authdb_event(auth_request),
		"bind search: base=%s filter=%s",
		srequest->base, srequest->filter);

	srequest->request.callback = ldap_bind_lookup_dn_callback;
        db_ldap_request(conn, &srequest->request);
}

static void
ldap_verify_plain_auth_bind_userdn(struct auth_request *auth_request,
				   struct passdb_ldap_request *request,
				   const struct ldap_pre_settings *ldap_set)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		container_of(_module, struct ldap_passdb_module, module);
	struct ldap_connection *conn = module->conn;
	struct ldap_request_bind *brequest = &request->request.bind;

	ldap_query_save_result(conn, auth_request, NULL, NULL);

	brequest->request.type = LDAP_REQUEST_TYPE_BIND;
	brequest->dn = p_strdup(auth_request->pool, ldap_set->passdb_ldap_bind_userdn);
        ldap_auth_bind(conn, brequest);
}

static void
ldap_verify_plain(struct auth_request *request,
		  const char *password ATTR_UNUSED,
		  verify_plain_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct ldap_passdb_module *module =
		container_of(_module, struct ldap_passdb_module, module);
	struct ldap_connection *conn = module->conn;
	struct event *event = authdb_event(request);
	struct passdb_ldap_request *ldap_request;
	const char *error;

	/* reconnect if needed. this is also done by db_ldap_search(), but
	   with auth binds we'll have to do it ourself */
	if (db_ldap_connect(conn)< 0) {
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	const struct ldap_pre_settings *ldap_pre = NULL;
	if (settings_get(event, &ldap_pre_setting_parser_info, 0,
			 &ldap_pre, &error) < 0 ||
	    ldap_pre_settings_post_check(ldap_pre, DB_LDAP_LOOKUP_TYPE_PASSDB,
					 &error) < 0) {
		e_error(event, "%s", error);
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		settings_free(ldap_pre);
		return;
	}

	ldap_request = p_new(request->pool, struct passdb_ldap_request, 1);
	ldap_request->callback.verify_plain = callback;

	auth_request_ref(request);
	ldap_request->request.ldap.auth_request = request;

	if (!ldap_pre->passdb_ldap_bind)
		ldap_lookup_pass(request, ldap_request, ldap_pre, TRUE);
	else if (*ldap_pre->passdb_ldap_bind_userdn == '\0')
		ldap_bind_lookup_dn(request, ldap_request, ldap_pre);
	else
		ldap_verify_plain_auth_bind_userdn(request, ldap_request, ldap_pre);

	settings_free(ldap_pre);
}

static void ldap_lookup_credentials(struct auth_request *request,
				    lookup_credentials_callback_t *callback)
{
	struct event *event = authdb_event(request);
	struct passdb_ldap_request *ldap_request =
		p_new(request->pool, struct passdb_ldap_request, 1);
	ldap_request->callback.lookup_credentials = callback;

	auth_request_ref(request);
	ldap_request->request.ldap.auth_request = request;

	const char *error;
	const struct ldap_pre_settings *ldap_pre = NULL;
	if (settings_get(event, &ldap_pre_setting_parser_info, 0,
			 &ldap_pre, &error) < 0 ||
	    ldap_pre_settings_post_check(ldap_pre, DB_LDAP_LOOKUP_TYPE_PASSDB,
					 &error) < 0) {
		e_error(event, "%s", error);
		passdb_ldap_request_fail(ldap_request, PASSDB_RESULT_INTERNAL_FAILURE);
		settings_free(ldap_pre);
		return;
	}

	/* with auth_bind=yes we don't necessarily have a password.
	   this will fail actual password credentials lookups, but it's fine
	   for passdb lookups done by lmtp/doveadm */
	bool require_password = !ldap_pre->passdb_ldap_bind;
        ldap_lookup_pass(request, ldap_request, ldap_pre, require_password);
	settings_free(ldap_pre);
}

static int passdb_ldap_preinit(pool_t pool, struct event *event,
		   	       struct passdb_module **module_r,
			       const char **error_r)
{
	const struct auth_passdb_post_settings *auth_post = NULL;
	const struct ldap_pre_settings *ldap_pre = NULL;
	struct ldap_passdb_module *module;
	int ret = -1;

	if (settings_get(event, &auth_passdb_post_setting_parser_info,
			 RAW_SETTINGS, &auth_post, error_r) < 0)
		goto failed;
	if (settings_get(event, &ldap_pre_setting_parser_info,
			 RAW_SETTINGS, &ldap_pre, error_r) < 0)
		goto failed;

	module = p_new(pool, struct ldap_passdb_module, 1);
	module->conn = db_ldap_init(event);

	db_ldap_get_attribute_names(pool, &auth_post->fields,
				    &module->attributes,
				    &module->sensitive_attr_names,
				    ldap_pre->passdb_ldap_bind ?
				    	"password" : NULL);

	module->module.default_cache_key = auth_cache_parse_key_and_fields(
		pool, t_strconcat(ldap_pre->ldap_base,
				  ldap_pre->passdb_ldap_filter, NULL),
		&auth_post->fields, NULL);

	*module_r = &module->module;
	ret = 0;

failed:
	settings_free(auth_post);
	settings_free(ldap_pre);
	return ret;
}

static void passdb_ldap_init(struct passdb_module *_module)
{
	struct ldap_passdb_module *module =
		container_of(_module, struct ldap_passdb_module, module);

	if (!module->module.blocking || worker)
		db_ldap_connect_delayed(module->conn);
}

static void passdb_ldap_deinit(struct passdb_module *_module)
{
	struct ldap_passdb_module *module =
		container_of(_module, struct ldap_passdb_module, module);

	db_ldap_unref(&module->conn);
}

#ifndef PLUGIN_BUILD
struct passdb_module_interface passdb_ldap =
#else
struct passdb_module_interface passdb_ldap_plugin =
#endif
{
	.name = "ldap",

	.preinit = passdb_ldap_preinit,
	.init = passdb_ldap_init,
	.deinit = passdb_ldap_deinit,

	.verify_plain = ldap_verify_plain,
	.lookup_credentials = ldap_lookup_credentials,
};
#else
struct passdb_module_interface passdb_ldap = {
	.name = "ldap"
};
#endif
