/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#if defined(USERDB_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))

#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "var-expand.h"
#include "auth-cache.h"
#include "db-ldap.h"

#include <ldap.h>
#include <stdlib.h>

struct ldap_userdb_module {
	struct userdb_module module;

	struct ldap_connection *conn;
};

struct userdb_ldap_request {
	struct ldap_request_search request;
	userdb_callback_t *userdb_callback;
	unsigned int entries;
};

struct userdb_iter_ldap_request {
	struct ldap_request_search request;
	struct ldap_userdb_iterate_context *ctx;
	userdb_callback_t *userdb_callback;
};

struct ldap_userdb_iterate_context {
	struct userdb_iterate_context ctx;
	struct userdb_iter_ldap_request request;
	pool_t pool;
	struct ldap_connection *conn;
	bool continued, in_callback;
};

static void
ldap_query_get_result(struct ldap_connection *conn, LDAPMessage *entry,
		      struct auth_request *auth_request)
{
	struct db_ldap_result_iterate_context *ldap_iter;
	const char *name, *const *values;

	auth_request_init_userdb_reply(auth_request);

	ldap_iter = db_ldap_result_iterate_init(conn, entry, auth_request,
						conn->user_attr_map);
	while (db_ldap_result_iterate_next(ldap_iter, &name, &values)) {
		auth_request_set_userdb_field_values(auth_request,
						     name, values);
	}
}

static void
userdb_ldap_lookup_finish(struct auth_request *auth_request,
			  struct userdb_ldap_request *urequest,
			  LDAPMessage *res)
{
	enum userdb_result result = USERDB_RESULT_INTERNAL_FAILURE;

	if (res == NULL) {
		result = USERDB_RESULT_INTERNAL_FAILURE;
	} else if (urequest->entries == 0) {
		result = USERDB_RESULT_USER_UNKNOWN;
		auth_request_log_info(auth_request, "ldap",
				      "unknown user");
	} else if (urequest->entries > 1) {
		auth_request_log_error(auth_request, "ldap",
			"user_filter matched multiple objects, aborting");
		result = USERDB_RESULT_INTERNAL_FAILURE;
	} else {
		result = USERDB_RESULT_OK;
	}

	urequest->userdb_callback(result, auth_request);
}

static void userdb_ldap_lookup_callback(struct ldap_connection *conn,
					struct ldap_request *request,
					LDAPMessage *res)
{
	struct userdb_ldap_request *urequest =
		(struct userdb_ldap_request *) request;
	struct auth_request *auth_request =
		urequest->request.request.auth_request;

	if (res == NULL || ldap_msgtype(res) == LDAP_RES_SEARCH_RESULT) {
		userdb_ldap_lookup_finish(auth_request, urequest, res);
		auth_request_unref(&auth_request);
		return;
	}

	if (urequest->entries++ == 0) {
		/* first entry */
		ldap_query_get_result(conn, res, auth_request);
	}
}

static void userdb_ldap_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct ldap_userdb_module *module =
		(struct ldap_userdb_module *)_module;
	struct ldap_connection *conn = module->conn;
        const struct var_expand_table *vars;
	const char **attr_names = (const char **)conn->user_attr_names;
	struct userdb_ldap_request *request;
	string_t *str;

	auth_request_ref(auth_request);
	request = p_new(auth_request->pool, struct userdb_ldap_request, 1);
	request->userdb_callback = callback;

	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);

	str = t_str_new(512);
	var_expand(str, conn->set.base, vars);
	request->request.base = p_strdup(auth_request->pool, str_c(str));

	str_truncate(str, 0);
	var_expand(str, conn->set.user_filter, vars);
	request->request.filter = p_strdup(auth_request->pool, str_c(str));

	request->request.attributes = conn->user_attr_names;

	auth_request_log_debug(auth_request, "ldap", "user search: "
			       "base=%s scope=%s filter=%s fields=%s",
			       request->request.base, conn->set.scope,
			       request->request.filter,
			       attr_names == NULL ? "(all)" :
			       t_strarray_join(attr_names, ","));

	request->request.request.auth_request = auth_request;
	request->request.request.callback = userdb_ldap_lookup_callback;
	db_ldap_request(conn, &request->request.request);
}

static void userdb_ldap_iterate_callback(struct ldap_connection *conn,
					 struct ldap_request *request,
					 LDAPMessage *res)
{
	struct userdb_iter_ldap_request *urequest =
		(struct userdb_iter_ldap_request *)request;
	struct ldap_userdb_iterate_context *ctx = urequest->ctx;
	struct db_ldap_result_iterate_context *ldap_iter;
	const char *name, *const *values;

	if (res == NULL || ldap_msgtype(res) == LDAP_RES_SEARCH_RESULT) {
		if (res == NULL)
			ctx->ctx.failed = TRUE;
		ctx->ctx.callback(NULL, ctx->ctx.context);
		return;
	}

	/* the iteration can take a while. reset the request's create time so
	   it won't be aborted while it's still running */
	request->create_time = ioloop_time;

	ctx->in_callback = TRUE;
	ldap_iter = db_ldap_result_iterate_init(conn, res,
						request->auth_request,
						conn->iterate_attr_map);
	while (db_ldap_result_iterate_next(ldap_iter, &name, &values)) {
		if (strcmp(name, "user") != 0) {
			i_warning("ldap: iterate: "
				  "Ignoring field not named 'user': %s", name);
			continue;
		}
		for (; *values != NULL; values++) {
			ctx->continued = FALSE;
			ctx->ctx.callback(*values, ctx->ctx.context);
		}
	}
	if (!ctx->continued)
		db_ldap_enable_input(conn, FALSE);
	ctx->in_callback = FALSE;
}

static struct userdb_iterate_context *
userdb_ldap_iterate_init(struct userdb_module *userdb,
			 userdb_iter_callback_t *callback, void *context)
{
	static struct var_expand_table static_tab[] = {
		/* nothing for now, but e.g. %{hostname} can be used */
		{ '\0', NULL, NULL }
	};
	struct ldap_userdb_module *module =
		(struct ldap_userdb_module *)userdb;
	struct ldap_connection *conn = module->conn;
	struct ldap_userdb_iterate_context *ctx;
	struct userdb_iter_ldap_request *request;
	const char **attr_names = (const char **)conn->iterate_attr_names;
	string_t *str;

	ctx = i_new(struct ldap_userdb_iterate_context, 1);
	ctx->ctx.userdb = userdb;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
	ctx->conn = conn;
	request = &ctx->request;
	request->ctx = ctx;

	request->request.request.auth_request = auth_request_new_dummy();
	request->request.base = conn->set.base;

	str = t_str_new(512);
	var_expand(str, conn->set.iterate_filter, static_tab);
	request->request.filter =
		p_strdup(request->request.request.auth_request->pool,
			 str_c(str));
	request->request.attributes = conn->iterate_attr_names;

	if (global_auth_settings->debug) {
		i_debug("ldap: iterate: base=%s scope=%s filter=%s fields=%s",
			conn->set.base, conn->set.scope,
			request->request.filter, attr_names == NULL ? "(all)" :
			t_strarray_join(attr_names, ","));
	}
	request->request.request.callback = userdb_ldap_iterate_callback;
	db_ldap_request(conn, &request->request.request);
	return &ctx->ctx;
}

static void userdb_ldap_iterate_next(struct userdb_iterate_context *_ctx)
{
	struct ldap_userdb_iterate_context *ctx =
		(struct ldap_userdb_iterate_context *)_ctx;

	ctx->continued = TRUE;
	if (!ctx->in_callback)
		db_ldap_enable_input(ctx->conn, TRUE);
}

static int userdb_ldap_iterate_deinit(struct userdb_iterate_context *_ctx)
{
	struct ldap_userdb_iterate_context *ctx =
		(struct ldap_userdb_iterate_context *)_ctx;
	int ret = _ctx->failed ? -1 : 0;

	db_ldap_enable_input(ctx->conn, TRUE);
	auth_request_unref(&ctx->request.request.request.auth_request);
	i_free(ctx);
	return ret;
}

static struct userdb_module *
userdb_ldap_preinit(pool_t pool, const char *args)
{
	struct ldap_userdb_module *module;
	struct ldap_connection *conn;

	module = p_new(pool, struct ldap_userdb_module, 1);
	module->conn = conn = db_ldap_init(args);
	conn->user_attr_map =
		hash_table_create(default_pool, conn->pool, 0, strcase_hash,
				  (hash_cmp_callback_t *)strcasecmp);
	conn->iterate_attr_map =
		hash_table_create(default_pool, conn->pool, 0, strcase_hash,
				  (hash_cmp_callback_t *)strcasecmp);

	db_ldap_set_attrs(conn, conn->set.user_attrs, &conn->user_attr_names,
			  conn->user_attr_map, NULL);
	db_ldap_set_attrs(conn, conn->set.iterate_attrs,
			  &conn->iterate_attr_names,
			  conn->iterate_attr_map, NULL);
	module->module.cache_key =
		auth_cache_parse_key(pool,
				     t_strconcat(conn->set.base,
						 conn->set.user_filter, NULL));
	return &module->module;
}

static void userdb_ldap_init(struct userdb_module *_module)
{
	struct ldap_userdb_module *module =
		(struct ldap_userdb_module *)_module;

	(void)db_ldap_connect(module->conn);
}

static void userdb_ldap_deinit(struct userdb_module *_module)
{
	struct ldap_userdb_module *module =
		(struct ldap_userdb_module *)_module;

	db_ldap_unref(&module->conn);
}

#ifndef PLUGIN_BUILD
struct userdb_module_interface userdb_ldap =
#else
struct userdb_module_interface userdb_ldap_plugin =
#endif
{
	"ldap",

	userdb_ldap_preinit,
	userdb_ldap_init,
	userdb_ldap_deinit,

	userdb_ldap_lookup,

	userdb_ldap_iterate_init,
	userdb_ldap_iterate_next,
	userdb_ldap_iterate_deinit
};
#else
struct userdb_module_interface userdb_ldap = {
	.name = "ldap"
};
#endif
