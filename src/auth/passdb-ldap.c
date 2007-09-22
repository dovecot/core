/* Copyright (c) 2003-2007 Dovecot authors, see the included COPYING file */

#include "common.h"

#ifdef PASSDB_LDAP

#include "hash.h"
#include "str.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "db-ldap.h"
#include "passdb.h"

#include <ldap.h>
#include <stdlib.h>

struct ldap_passdb_module {
	struct passdb_module module;

	struct ldap_connection *conn;
};

struct passdb_ldap_request {
	struct ldap_request request;

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
	int ret;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;

	if (res != NULL) {
		/* LDAP query returned something */
		ret = ldap_result2error(conn->ld, res, 0);
		if (ret != LDAP_SUCCESS) {
			auth_request_log_error(auth_request, "ldap",
					       "ldap_search(%s) failed: %s",
					       request->request.filter,
					       ldap_err2string(ret));
		} else {
			/* get the reply */
			entry = ldap_first_entry(conn->ld, res);
			if (entry != NULL) {
				/* success */
				return entry;
			}

			/* no entries returned */
			auth_request_log_info(auth_request, "ldap",
					      "unknown user");
			passdb_result = PASSDB_RESULT_USER_UNKNOWN;
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

static void handle_request(struct ldap_connection *conn,
			   struct ldap_request *request, LDAPMessage *res)
{
	struct passdb_ldap_request *ldap_request =
		(struct passdb_ldap_request *)request;
        struct auth_request *auth_request = request->context;
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
			"Empty password returned without no_password");
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

	/* LDAP's RFC2307 specifies the MD5 scheme for what we call PLAIN-MD5.
	   We can detect this case, because base64 doesn't use '$'. */
	if (scheme != NULL && strncasecmp(scheme, "MD5", 3) == 0 &&
	    strncmp(password, "$1$", 3) != 0) {
		auth_request_log_debug(auth_request, "ldap",
				       "Password doesn't look like MD5-CRYPT, "
				       "scheme changed to PLAIN-MD5");
		scheme = "PLAIN-MD5";
	}

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

static void authbind_start(struct ldap_connection *conn,
			   struct ldap_request *ldap_request)
{
	struct passdb_ldap_request *passdb_ldap_request =
		(struct passdb_ldap_request *)ldap_request;
	struct auth_request *auth_request = ldap_request->context;
	int msgid;

	i_assert(ldap_request->base != NULL);

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

	if (conn->connected && hash_count(conn->requests) == 0) {
		/* switch back to the default dn before doing the next search
		   request */
		conn->last_auth_bind = TRUE;
		i_assert(!conn->binding);

		/* the DN is kept in base variable, a bit ugly.. */
		msgid = ldap_bind(conn->ld, ldap_request->base,
				  auth_request->mech_password,
				  LDAP_AUTH_SIMPLE);
		if (msgid == -1) {
			auth_request_log_error(auth_request, "ldap",
				"ldap_bind(%s) failed: %s",
				ldap_request->base, ldap_get_error(conn));
			passdb_ldap_request->callback.
				verify_plain(PASSDB_RESULT_INTERNAL_FAILURE,
					     auth_request);
			return;
		}

		conn->binding = TRUE;
		hash_insert(conn->requests, POINTER_CAST(msgid), ldap_request);

		auth_request_log_debug(auth_request, "ldap", "bind: dn=%s",
				       ldap_request->base);
	} else {
		db_ldap_add_delayed_request(conn, ldap_request);
	}

	/* Bind started */
	auth_request_ref(auth_request);
}

static void
handle_request_authbind(struct ldap_connection *conn,
			struct ldap_request *ldap_request, LDAPMessage *res)
{
	struct passdb_ldap_request *passdb_ldap_request =
		(struct passdb_ldap_request *)ldap_request;
	struct auth_request *auth_request = ldap_request->context;
	enum passdb_result passdb_result;
	int ret;

	conn->binding = FALSE;
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

	if (conn->retrying && res == NULL) {
		/* reconnected, retry binding */
		authbind_start(conn, ldap_request);
	} else {
		passdb_ldap_request->callback.
			verify_plain(passdb_result, auth_request);
	}
        auth_request_unref(&auth_request);
}

static void
handle_request_authbind_search(struct ldap_connection *conn,
			       struct ldap_request *ldap_request,
			       LDAPMessage *res)
{
	struct passdb_ldap_request *passdb_ldap_request =
		(struct passdb_ldap_request *)ldap_request;
	struct auth_request *auth_request = ldap_request->context;
	LDAPMessage *entry;
	char *dn;

	entry = handle_request_get_entry(conn, auth_request,
					 passdb_ldap_request, res);
	if (entry == NULL)
		return;

	ldap_query_save_result(conn, entry, auth_request);

	/* switch the handler to the authenticated bind handler */
	dn = ldap_get_dn(conn->ld, entry);
	ldap_request->base = p_strdup(auth_request->pool, dn);
	ldap_memfree(dn);

	ldap_request->filter = NULL;
	ldap_request->callback = handle_request_authbind;

        authbind_start(conn, ldap_request);
	auth_request_unref(&auth_request);
}

static void ldap_lookup_pass(struct auth_request *auth_request,
			     struct ldap_request *ldap_request)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct ldap_connection *conn = module->conn;
        const struct var_expand_table *vars;
	const char **attr_names = (const char **)conn->pass_attr_names;
	string_t *str;

	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);

	str = t_str_new(512);
	var_expand(str, conn->set.base, vars);
	ldap_request->base = p_strdup(auth_request->pool, str_c(str));

	str_truncate(str, 0);
	var_expand(str, conn->set.pass_filter, vars);
	ldap_request->filter = p_strdup(auth_request->pool, str_c(str));

	auth_request_ref(auth_request);
	ldap_request->callback = handle_request;
	ldap_request->context = auth_request;
	ldap_request->attributes = conn->pass_attr_names;

	auth_request_log_debug(auth_request, "ldap", "pass search: "
			       "base=%s scope=%s filter=%s fields=%s",
			       ldap_request->base, conn->set.scope,
			       ldap_request->filter,
			       attr_names == NULL ? "(all)" :
			       t_strarray_join(attr_names, ","));

	db_ldap_search(conn, ldap_request, conn->set.ldap_scope);
}

static void
ldap_verify_plain_auth_bind_userdn(struct auth_request *auth_request,
				   struct ldap_request *ldap_request)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct ldap_connection *conn = module->conn;
        const struct var_expand_table *vars;
	string_t *dn;

	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);
	dn = t_str_new(512);
	var_expand(dn, conn->set.auth_bind_userdn, vars);

	ldap_request->callback = handle_request_authbind;
	ldap_request->context = auth_request;

	ldap_request->base = p_strdup(auth_request->pool, str_c(dn));
        authbind_start(conn, ldap_request);
}

static void
ldap_verify_plain_authbind(struct auth_request *auth_request,
			   struct ldap_request *ldap_request)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct ldap_connection *conn = module->conn;
	const struct var_expand_table *vars;
	string_t *str;

	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);

	str = t_str_new(512);
	var_expand(str, conn->set.base, vars);
	ldap_request->base = p_strdup(auth_request->pool, str_c(str));

	str_truncate(str, 0);
	var_expand(str, conn->set.pass_filter, vars);
	ldap_request->filter = p_strdup(auth_request->pool, str_c(str));

	/* we don't need the attributes to perform authentication, but they
	   may contain some extra parameters. if a password is returned,
	   it's just ignored. */
	ldap_request->attributes = conn->pass_attr_names;

	auth_request_ref(auth_request);
	ldap_request->context = auth_request;
	ldap_request->callback = handle_request_authbind_search;

	auth_request_log_debug(auth_request, "ldap",
			       "bind search: base=%s filter=%s",
			       ldap_request->base, ldap_request->filter);

        db_ldap_search(conn, ldap_request, LDAP_SCOPE_SUBTREE);
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

	if (conn->set.auth_bind_userdn != NULL)
		ldap_verify_plain_auth_bind_userdn(request, &ldap_request->request);
	else if (conn->set.auth_bind)
		ldap_verify_plain_authbind(request, &ldap_request->request);
	else
		ldap_lookup_pass(request, &ldap_request->request);
}

static void ldap_lookup_credentials(struct auth_request *request,
				    lookup_credentials_callback_t *callback)
{
	struct passdb_ldap_request *ldap_request;

	ldap_request = p_new(request->pool, struct passdb_ldap_request, 1);
	ldap_request->callback.lookup_credentials = callback;

        ldap_lookup_pass(request, &ldap_request->request);
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

	if (conn->set.auth_bind_userdn != NULL)
		conn->set.auth_bind = TRUE;
	db_ldap_set_attrs(conn, conn->set.pass_attrs, &conn->pass_attr_names,
			  conn->pass_attr_map,
			  conn->set.auth_bind ? "password" : NULL);
	module->module.cache_key =
		auth_cache_parse_key(auth_passdb->auth->pool,
				     conn->set.pass_filter);
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

#endif
