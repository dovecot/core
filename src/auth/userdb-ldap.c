/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))

#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "auth-cache.h"
#include "settings.h"
#include "auth-settings.h"
#include "db-ldap.h"

#include <ldap.h>

#define RAW_SETTINGS (SETTINGS_GET_FLAG_NO_CHECK | SETTINGS_GET_FLAG_NO_EXPAND)

struct ldap_userdb_module {
	struct userdb_module module;

	struct ldap_connection *conn;
	const char *const *attributes;
	const char *const *sensitive_attr_names;
	const char *const *iterate_attributes;
};

struct userdb_ldap_request {
	struct ldap_request_search request;
	userdb_callback_t *userdb_callback;
	unsigned int entries;
	bool failed:1;
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
	bool continued, in_callback, deinitialized;
};

static int
ldap_query_get_result(struct ldap_connection *conn,
		      struct auth_request *auth_request,
		      struct ldap_request_search *ldap_request,
		      LDAPMessage *res)
{
	struct db_ldap_field_expand_context ctx = {
		.event = authdb_event(auth_request),
		.fields = ldap_query_get_fields(auth_request->pool, conn,
						ldap_request, res, FALSE)
	};

	return auth_request_set_userdb_fields_ex(auth_request, &ctx,
						 db_ldap_field_expand_fn_table);
}

static void
userdb_ldap_lookup_finish(struct auth_request *auth_request,
			  struct userdb_ldap_request *urequest,
			  LDAPMessage *res)
{
	enum userdb_result result = USERDB_RESULT_INTERNAL_FAILURE;

	if (res == NULL || urequest->failed) {
		result = USERDB_RESULT_INTERNAL_FAILURE;
	} else if (urequest->entries == 0) {
		result = USERDB_RESULT_USER_UNKNOWN;
		auth_request_db_log_unknown_user(auth_request);
	} else if (urequest->entries > 1) {
		e_error(authdb_event(auth_request),
			"userdb_ldap_filter matched multiple objects, aborting");
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
		container_of(request, struct userdb_ldap_request, request.request);

	struct auth_request *auth_request =
		urequest->request.request.auth_request;

	if (res == NULL || ldap_msgtype(res) == LDAP_RES_SEARCH_RESULT) {
		userdb_ldap_lookup_finish(auth_request, urequest, res);
		auth_request_unref(&auth_request);
		return;
	}

	if (urequest->entries++ == 0) {
		/* first entry */
		if (ldap_query_get_result(conn, auth_request,
					  &urequest->request, res) < 0)
			urequest->failed = TRUE;
	}
}

static void userdb_ldap_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct ldap_userdb_module *module =
		container_of(_module, struct ldap_userdb_module, module);
	struct ldap_connection *conn = module->conn;
	struct event *event = authdb_event(auth_request);

	struct userdb_ldap_request *request;
	const char *error;

	const struct ldap_pre_settings *ldap_pre = NULL;
	if (settings_get(event, &ldap_pre_setting_parser_info, 0,
			 &ldap_pre, &error) < 0 ||
	    ldap_pre_settings_post_check(ldap_pre, DB_LDAP_LOOKUP_TYPE_USERDB,
					 &error) < 0) {
		e_error(event, "%s", error);
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		settings_free(ldap_pre);
		return;
	}

	auth_request_ref(auth_request);
	request = p_new(auth_request->pool, struct userdb_ldap_request, 1);
	request->userdb_callback = callback;
	request->request.base = p_strdup(auth_request->pool,
					 ldap_pre->ldap_base);
	request->request.filter = p_strdup(auth_request->pool,
					   ldap_pre->userdb_ldap_filter);
	request->request.attributes = module->attributes;
	request->request.sensitive_attr_names = module->sensitive_attr_names;

	settings_free(ldap_pre);

	e_debug(event, "user search: base=%s scope=%s filter=%s fields=%s",
		request->request.base, conn->set->scope,
		request->request.filter,
		t_strarray_join(module->attributes, ","));

	request->request.request.auth_request = auth_request;
	request->request.request.callback = userdb_ldap_lookup_callback;
	db_ldap_request(conn, &request->request.request);
}

static void userdb_ldap_iterate_callback(struct ldap_connection *conn,
					 struct ldap_request *request,
					 LDAPMessage *res)
{
	struct userdb_iter_ldap_request *urequest =
		container_of(request, struct userdb_iter_ldap_request, request.request);
	struct ldap_userdb_iterate_context *ctx = urequest->ctx;

	if (res == NULL || ldap_msgtype(res) == LDAP_RES_SEARCH_RESULT) {
		if (res == NULL)
			ctx->ctx.failed = TRUE;
		if (!ctx->deinitialized)
			ctx->ctx.callback(NULL, ctx->ctx.context);
		auth_request_unref(&request->auth_request);
		return;
	}

	if (ctx->deinitialized)
		return;

	/* the iteration can take a while. reset the request's create time so
	   it won't be aborted while it's still running */
	request->create_time = ioloop_time;

	ctx->in_callback = TRUE;

	struct db_ldap_field_expand_context fctx = {
		.event = authdb_event(request->auth_request),
		.fields = ldap_query_get_fields(pool_datastack_create(), conn,
						&urequest->request, res, TRUE)
	};

	struct var_expand_params params = {
		.providers = db_ldap_field_expand_fn_table,
		.context = &fctx
	};

	struct event *event = event_create(authdb_event(urequest->request.request.auth_request));
	event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_PARAMS, &params);

	const struct ldap_post_settings *set;
	const char *error;
	if (settings_get(event, &ldap_post_setting_parser_info, 0,
			 &set, &error) < 0) {
		e_error(event, "%s", error);
		ctx->ctx.failed = TRUE;
	}
	else {
		unsigned int count;
		const char *const *items = array_get(&set->iterate_fields, &count);
		for (unsigned int ndx = 0; ndx < count - 1;) {
			const char *name = items[ndx++];
			const char *value = items[ndx++];
			if (strcmp(name, DB_LDAP_ATTR_MULTI_PREFIX"user") == 0) {
				value = t_strsplit(value, DB_LDAP_ATTR_SEPARATOR)[0];
				e_warning(authdb_event(request->auth_request),
					  "iterate: Taking only first value of %s: %s",
					  name + 1, value);
				continue;
			}
			if (strcmp(name, "user") != 0) {
				e_warning(authdb_event(request->auth_request),
					  "iterate: Ignoring field not named 'user': %s",
					  name);
				continue;
			}
			ctx->continued = FALSE;
			ctx->ctx.callback(value, ctx->ctx.context);
		}
		settings_free(set);
	}
	event_unref(&event);

	if (!ctx->continued)
		db_ldap_enable_input(conn, FALSE);
	ctx->in_callback = FALSE;
}

static struct userdb_iterate_context *
userdb_ldap_iterate_init(struct auth_request *auth_request,
			 userdb_iter_callback_t *callback, void *context)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct ldap_userdb_module *module =
		container_of(_module, struct ldap_userdb_module, module);
	struct ldap_connection *conn = module->conn;
	struct event *event = authdb_event(auth_request);

	struct ldap_userdb_iterate_context *ctx;
	struct userdb_iter_ldap_request *request;
	const char *error;

	ctx = p_new(auth_request->pool, struct ldap_userdb_iterate_context, 1);
	ctx->ctx.auth_request = auth_request;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
	ctx->conn = conn;
	request = &ctx->request;
	request->ctx = ctx;

	const struct ldap_pre_settings *ldap_pre = NULL;
	if (settings_get(event, &ldap_pre_setting_parser_info, 0,
			 &ldap_pre, &error) < 0 ||
	    ldap_pre_settings_post_check(ldap_pre, DB_LDAP_LOOKUP_TYPE_ITERATE,
					 &error) < 0) {
		e_error(event, "%s", error);
		settings_free(ldap_pre);
		ctx->ctx.failed = TRUE;
		return &ctx->ctx;
	}

	auth_request_ref(auth_request);
	request->request.request.auth_request = auth_request;
	request->request.base = p_strdup(auth_request->pool,
					 ldap_pre->ldap_base);
	request->request.filter = p_strdup(auth_request->pool,
					   ldap_pre->userdb_ldap_iterate_filter);
	request->request.attributes = module->iterate_attributes;
	request->request.sensitive_attr_names = module->sensitive_attr_names;
	request->request.multi_entry = TRUE;
	settings_free(ldap_pre);

	e_debug(event, "ldap: iterate: base=%s scope=%s filter=%s fields=%s",
		request->request.base, conn->set->scope,
		request->request.filter,
		t_strarray_join(module->iterate_attributes, ","));

	request->request.request.callback = userdb_ldap_iterate_callback;
	db_ldap_request(conn, &request->request.request);
	return &ctx->ctx;
}

static void userdb_ldap_iterate_next(struct userdb_iterate_context *_ctx)
{
	struct ldap_userdb_iterate_context *ctx =
		container_of(_ctx, struct ldap_userdb_iterate_context, ctx);

	if (_ctx->failed) {
		_ctx->callback(NULL, _ctx->context);
		return;
	}
	ctx->continued = TRUE;
	if (!ctx->in_callback)
		db_ldap_enable_input(ctx->conn, TRUE);
}

static int userdb_ldap_iterate_deinit(struct userdb_iterate_context *_ctx)
{
	struct ldap_userdb_iterate_context *ctx =
		container_of(_ctx, struct ldap_userdb_iterate_context, ctx);
	int ret = _ctx->failed ? -1 : 0;

	db_ldap_enable_input(ctx->conn, TRUE);
	ctx->deinitialized = TRUE;
	return ret;
}

static int userdb_ldap_preinit(pool_t pool, struct event *event,
			       struct userdb_module **module_r,
			       const char **error_r ATTR_UNUSED)
{
	const struct auth_userdb_post_settings *auth_post = NULL;
	const struct ldap_post_settings *ldap_post = NULL;
	const struct ldap_pre_settings *ldap_pre = NULL;
	struct ldap_userdb_module *module;
	int ret = -1;

	if (settings_get(event, &auth_userdb_post_setting_parser_info,
			 RAW_SETTINGS, &auth_post, error_r) < 0)
		goto failed;
	if (settings_get(event, &ldap_post_setting_parser_info,
			 RAW_SETTINGS, &ldap_post, error_r) < 0)
		goto failed;
	if (settings_get(event, &ldap_pre_setting_parser_info,
			 RAW_SETTINGS, &ldap_pre, error_r) < 0)
		goto failed;

	module = p_new(pool, struct ldap_userdb_module, 1);
	module->conn = db_ldap_init(event);

	db_ldap_get_attribute_names(pool, &auth_post->fields,
				    &module->attributes,
				    &module->sensitive_attr_names, NULL);
	db_ldap_get_attribute_names(pool, &ldap_post->iterate_fields,
				    &module->iterate_attributes, NULL, NULL);

	module->module.default_cache_key = auth_cache_parse_key_and_fields(
		pool, t_strconcat(ldap_pre->ldap_base,
				  ldap_pre->userdb_ldap_filter, NULL),
		&auth_post->fields, NULL);

	*module_r = &module->module;
	ret = 0;

failed:
	settings_free(auth_post);
	settings_free(ldap_pre);
	settings_free(ldap_post);
	return ret;
}

static void userdb_ldap_init(struct userdb_module *_module)
{
	struct ldap_userdb_module *module =
		container_of(_module, struct ldap_userdb_module, module);

	if (!module->module.blocking || worker)
		db_ldap_connect_delayed(module->conn);
}

static void userdb_ldap_deinit(struct userdb_module *_module)
{
	struct ldap_userdb_module *module =
		container_of(_module, struct ldap_userdb_module, module);

	db_ldap_unref(&module->conn);
}

#ifndef PLUGIN_BUILD
struct userdb_module_interface userdb_ldap =
#else
struct userdb_module_interface userdb_ldap_plugin =
#endif
{
	.name = "ldap",

	.preinit = userdb_ldap_preinit,
	.init = userdb_ldap_init,
	.deinit = userdb_ldap_deinit,

	.lookup = userdb_ldap_lookup,

	.iterate_init = userdb_ldap_iterate_init,
	.iterate_next = userdb_ldap_iterate_next,
	.iterate_deinit = userdb_ldap_iterate_deinit
};
#else
struct userdb_module_interface userdb_ldap = {
	.name = "ldap"
};
#endif
