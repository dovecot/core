/* Copyright (C) 2003 Timo Sirainen */

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

static const char *default_attr_map[] = {
	"user", "password", NULL
};

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

static void
ldap_query_save_result(struct ldap_connection *conn, LDAPMessage *entry,
		       struct auth_request *auth_request)
{
	BerElement *ber;
	const char *name;
	char *attr, **vals;
	unsigned int i;
	string_t *debug = NULL;

	attr = ldap_first_attribute(conn->ld, entry, &ber);
	while (attr != NULL) {
		name = hash_lookup(conn->pass_attr_map, attr);
		vals = ldap_get_values(conn->ld, entry, attr);

		if (auth_request->auth->verbose_debug) {
			if (debug == NULL)
				debug = t_str_new(256);
			else
				str_append_c(debug, ' ');
			str_append(debug, attr);
			str_printfa(debug, "(%s)=",
				    name != NULL ? name : "?unknown?");
		}

		if (name != NULL && vals != NULL) {
			for (i = 0; vals[i] != NULL; i++) {
				if (debug != NULL) {
					if (i != 0)
						str_append_c(debug, '/');
					str_append(debug, vals[i]);
				}
				auth_request_set_field(auth_request,
						name, vals[i],
						conn->set.default_pass_scheme);
			}
		}

		ldap_value_free(vals);
		ldap_memfree(attr);

		attr = ldap_next_attribute(conn->ld, entry, ber);
	}

	if (debug != NULL) {
		auth_request_log_debug(auth_request, "ldap",
				       "%s", str_c(debug));
	}
}

static LDAPMessage *
handle_request_get_entry(struct ldap_connection *conn,
			 struct auth_request *auth_request,
			 struct passdb_ldap_request *request, LDAPMessage *res)
{
	enum passdb_result passdb_result;
	LDAPMessage *entry;
	int ret;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;

	if (!auth_request_unref(auth_request)) {
		/* Auth request is already aborted */
	} else if (res != NULL) {
		/* LDAP query returned something */
		ret = ldap_result2error(conn->ld, res, 0);
		if (ret != LDAP_SUCCESS) {
			auth_request_log_error(auth_request, "ldap",
					       "ldap_search() failed: %s",
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

	request->callback.verify_plain(passdb_result, auth_request);
	return NULL;
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
				       "Multiple password replies");
	} else {
		password = auth_request->passdb_password;
		if (password == NULL)
			auth_request->no_password = TRUE;
		passdb_result = PASSDB_RESULT_OK;
	}

	scheme = password_get_scheme(&password);
	/* auth_request_set_field() sets scheme */
	i_assert(password == NULL || scheme != NULL);

	if (auth_request->credentials != -1) {
		passdb_handle_credentials(passdb_result, password, scheme,
			ldap_request->callback.lookup_credentials,
			auth_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		ldap_request->callback.verify_plain(passdb_result,
						    auth_request);
		return;
	}

	ret = password_verify(auth_request->mech_password, password, scheme,
			      auth_request->user);
	if (ret < 0) {
		auth_request_log_error(auth_request, "ldap",
			"Unknown password scheme %s", scheme);
	} else if (ret == 0) {
		auth_request_log_info(auth_request, "ldap",
				      "password mismatch");
	}

	ldap_request->callback.verify_plain(ret > 0 ? PASSDB_RESULT_OK :
					    PASSDB_RESULT_PASSWORD_MISMATCH,
					    auth_request);
}

static void
handle_request_authbind(struct ldap_connection *conn,
			struct ldap_request *request, LDAPMessage *res)
{
	struct passdb_ldap_request *passdb_ldap_request =
		(struct passdb_ldap_request *)request;
	struct auth_request *auth_request = request->context;
	enum passdb_result passdb_result;
	int ret;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;

	if (!auth_request_unref(auth_request)) {
		/* Auth request is already aborted */
	} else if (res != NULL) {
		ret = ldap_result2error(conn->ld, res, 0);
		if (ret == LDAP_SUCCESS)
			passdb_result = PASSDB_RESULT_OK;
		else if (ret == LDAP_INVALID_CREDENTIALS)
			passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
		else {
			auth_request_log_error(request->context, "ldap",
					       "ldap_bind() failed: %s",
					       ldap_err2string(ret));
		}
	}

	passdb_ldap_request->callback.verify_plain(passdb_result, auth_request);
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
	const char *dn;
	int msgid;

	entry = handle_request_get_entry(conn, auth_request,
					 passdb_ldap_request, res);
	if (entry == NULL)
		return;

	dn = ldap_get_dn(conn->ld, entry);

	/* switch the handler to the authenticated bind handler */
	ldap_request->callback = handle_request_authbind;

	msgid = ldap_bind(conn->ld, dn, auth_request->mech_password,
			  LDAP_AUTH_SIMPLE);
	if (msgid == -1) {
		i_error("ldap_bind() failed: %s", ldap_get_error(conn));
		passdb_ldap_request->callback.
			verify_plain(PASSDB_RESULT_INTERNAL_FAILURE,
				     auth_request);
		return;
	}

	/* Bind started */
	auth_request_ref(auth_request);
	hash_insert(conn->requests, POINTER_CAST(msgid), ldap_request);
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

	auth_request_log_debug(auth_request, "ldap",
			       "base=%s scope=%s filter=%s fields=%s",
			       ldap_request->base, conn->set.scope,
			       ldap_request->filter,
			       t_strarray_join(attr_names, ","));

	db_ldap_search(conn, ldap_request, conn->set.ldap_scope);
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

	/* we don't want any attributes in our search results;
	   we only need the DN. */
	ldap_request->attributes = p_new(auth_request->pool, char *, 1);

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
		  const char *password __attr_unused__,
		  verify_plain_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct ldap_passdb_module *module =
		(struct ldap_passdb_module *)_module;
	struct ldap_connection *conn = module->conn;
	struct passdb_ldap_request *ldap_request;

	ldap_request = p_new(request->pool, struct passdb_ldap_request, 1);
	ldap_request->callback.verify_plain = callback;

	if (conn->set.auth_bind)
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

	db_ldap_set_attrs(conn, conn->set.pass_attrs, &conn->pass_attr_names,
			  conn->pass_attr_map, default_attr_map);
	module->module.cache_key =
		auth_cache_parse_key(auth_passdb->auth->pool,
				     conn->set.pass_filter);
	module->module.default_pass_scheme = conn->set.default_pass_scheme;
	return &module->module;
}

static void passdb_ldap_init(struct passdb_module *_module,
			     const char *args __attr_unused__)
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

	db_ldap_unref(module->conn);
}

struct passdb_module_interface passdb_ldap = {
	"ldap",

	passdb_ldap_preinit,
	passdb_ldap_init,
	passdb_ldap_deinit,

	ldap_verify_plain,
	ldap_lookup_credentials
};

#endif
