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

struct ldap_query_save_context {
	struct ldap_connection *conn;
	struct auth_request *auth_request;
	LDAPMessage *entry;

	string_t *debug;
	unsigned int userdb_fields:1;
	unsigned int add_userdb_uid:1;
	unsigned int add_userdb_gid:1;
};

static void
ldap_query_save_attr(struct ldap_query_save_context *ctx, const char *attr)
{
	struct auth *auth = ctx->auth_request->auth;
	const char *name;
	char **vals;
	unsigned int i;

	name = hash_lookup(ctx->conn->pass_attr_map, attr);

	if (auth->verbose_debug) {
		if (ctx->debug == NULL)
			ctx->debug = t_str_new(256);
		else
			str_append_c(ctx->debug, ' ');
		str_append(ctx->debug, attr);
		str_printfa(ctx->debug, "(%s)=",
			    name != NULL ? name : "?unknown?");
	}

	if (name == NULL)
		return;

	if (strncmp(name, "userdb_", 7) == 0) {
		/* in case we're trying to use prefetch userdb,
		   see if we need to add global uid/gid */
		if (!ctx->userdb_fields) {
			ctx->add_userdb_uid = ctx->add_userdb_gid = TRUE;
			ctx->userdb_fields = TRUE;
		}
		if (strcmp(name, "userdb_uid") == 0)
			ctx->add_userdb_uid = FALSE;
		else if (strcmp(name, "userdb_gid") == 0)
			ctx->add_userdb_gid = FALSE;
	}

	vals = ldap_get_values(ctx->conn->ld, ctx->entry, attr);
	if (vals != NULL && *name != '\0') {
		for (i = 0; vals[i] != NULL; i++) {
			if (ctx->debug != NULL) {
				if (i != 0)
					str_append_c(ctx->debug, '/');
				if (auth->verbose_debug_passwords ||
				    strcmp(name, "password") != 0)
					str_append(ctx->debug, vals[i]);
				else {
					str_append(ctx->debug,
						   PASSWORD_HIDDEN_STR);
				}
			}
			auth_request_set_field(ctx->auth_request, name, vals[i],
					ctx->conn->set.default_pass_scheme);
		}
	}

	ldap_value_free(vals);
}

static void
ldap_query_save_result(struct ldap_connection *conn, LDAPMessage *entry,
		       struct auth_request *auth_request)
{
	struct ldap_query_save_context ctx;
	BerElement *ber;
	char *attr;

	memset(&ctx, 0, sizeof(ctx));
	ctx.conn = conn;
	ctx.auth_request = auth_request;
	ctx.entry = entry;

	attr = ldap_first_attribute(conn->ld, entry, &ber);
	while (attr != NULL) {
		ldap_query_save_attr(&ctx, attr);
		ldap_memfree(attr);

		attr = ldap_next_attribute(conn->ld, entry, ber);
	}

	if (ctx.add_userdb_uid && conn->set.uid != (uid_t)-1) {
		auth_request_set_field(auth_request, "userdb_uid",
				       dec2str(conn->set.uid), NULL);
	}
	if (ctx.add_userdb_gid && conn->set.gid != (gid_t)-1) {
		auth_request_set_field(auth_request, "userdb_gid",
				       dec2str(conn->set.gid), NULL);
	}

	if (ctx.debug != NULL) {
		auth_request_log_debug(auth_request, "ldap",
				       "result: %s", str_c(ctx.debug));
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

	request->callback.verify_plain(passdb_result, auth_request);
	auth_request_unref(&auth_request);
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
		/* passdb_password may change on the way,
		   so we'll need to strdup. */
		password = t_strdup(auth_request->passdb_password);
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

	if (conn->connected && hash_size(conn->requests) == 0) {
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

	entry = handle_request_get_entry(conn, auth_request,
					 passdb_ldap_request, res);
	if (entry == NULL)
		return;

	ldap_query_save_result(conn, entry, auth_request);

	/* switch the handler to the authenticated bind handler */
	ldap_request->base =
		p_strdup(auth_request->pool, ldap_get_dn(conn->ld, entry));
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
		  const char *password __attr_unused__,
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
			  conn->pass_attr_map, default_attr_map,
			  conn->set.auth_bind ? "password" : NULL);
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
