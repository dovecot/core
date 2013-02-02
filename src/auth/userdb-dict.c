/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "auth-cache.h"
#include "db-dict.h"

#include <dict.h>
#include <stdlib.h>

struct dict_userdb_module {
	struct userdb_module module;

	struct dict_connection *conn;
};

struct dict_userdb_iterate_context {
	struct userdb_iterate_context ctx;

	userdb_callback_t *userdb_callback;
	const char *key_prefix;
	unsigned int key_prefix_len;
	struct dict_iterate_context *iter;
};

static int
dict_query_save_results(struct auth_request *auth_request,
			struct dict_connection *conn, const char *result)
{
	struct db_dict_value_iter *iter;
	const char *key, *value, *error;

	auth_request_init_userdb_reply(auth_request);

	iter = db_dict_value_iter_init(conn, result);
	while (db_dict_value_iter_next(iter, &key, &value)) {
		if (value != NULL)
			auth_request_set_userdb_field(auth_request, key, value);
	}
	if (db_dict_value_iter_deinit(&iter, &error) < 0) {
		auth_request_log_error(auth_request, "dict",
			"Value '%s' not in valid %s format: %s",
			result, conn->set.value_format, error);
		return -1;
	}
	return 0;
}

static void userdb_dict_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct dict_userdb_module *module =
		(struct dict_userdb_module *)_module;
	string_t *key;
	enum userdb_result userdb_result;
	const char *value;
	int ret;

	if (*module->conn->set.user_key == '\0') {
		auth_request_log_error(auth_request, "dict",
				       "user_key not specified");
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	}

	key = t_str_new(512);
	str_append(key, DICT_PATH_SHARED);
	var_expand(key, module->conn->set.user_key,
		   auth_request_get_var_expand_table(auth_request, NULL));

	auth_request_log_debug(auth_request, "dict", "lookup %s", str_c(key));
	ret = dict_lookup(module->conn->dict, pool_datastack_create(),
			  str_c(key), &value);
	if (ret < 0) {
		auth_request_log_error(auth_request, "dict", "Lookup failed");
		userdb_result = USERDB_RESULT_INTERNAL_FAILURE;
	} else if (ret == 0) {
		auth_request_log_info(auth_request, "dict", "unknown user");
		userdb_result = USERDB_RESULT_USER_UNKNOWN;
	} else {
		auth_request_log_debug(auth_request, "dict",
				       "result: %s", value);
		if (dict_query_save_results(auth_request, module->conn, value) < 0)
			userdb_result = USERDB_RESULT_INTERNAL_FAILURE;
		else
			userdb_result = USERDB_RESULT_OK;
 	}
	callback(userdb_result, auth_request);
}

static struct userdb_iterate_context *
userdb_dict_iterate_init(struct auth_request *auth_request,
			 userdb_iter_callback_t *callback, void *context)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct dict_userdb_module *module =
		(struct dict_userdb_module *)_module;
	struct dict_userdb_iterate_context *ctx;
        const struct var_expand_table *vars;
	string_t *path;

	ctx = i_new(struct dict_userdb_iterate_context, 1);
	ctx->ctx.auth_request = auth_request;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
	auth_request_ref(auth_request);

	if (*module->conn->set.iterate_prefix == '\0') {
		if (!module->conn->set.iterate_disable) {
			auth_request_log_error(auth_request, "dict",
					       "iterate: iterate_prefix not set");
			ctx->ctx.failed = TRUE;
		}
		return &ctx->ctx;
	}

	path = t_str_new(128);
	str_append(path, DICT_PATH_SHARED);
	vars = auth_request_get_var_expand_table(auth_request, NULL);
	var_expand(path, module->conn->set.iterate_prefix, vars);
	ctx->key_prefix = p_strdup(auth_request->pool, str_c(path));
	ctx->key_prefix_len = strlen(ctx->key_prefix);

	ctx->iter = dict_iterate_init(module->conn->dict, ctx->key_prefix, 0);
	auth_request_log_debug(auth_request, "dict", "iterate: prefix=%s",
			       ctx->key_prefix);
	return &ctx->ctx;
}

static const char *
userdb_dict_get_user(struct dict_userdb_iterate_context *ctx, const char *key)
{
	i_assert(strncmp(key, ctx->key_prefix, ctx->key_prefix_len) == 0);

	return key + ctx->key_prefix_len;
}

static void userdb_dict_iterate_next(struct userdb_iterate_context *_ctx)
{
	struct dict_userdb_iterate_context *ctx =
		(struct dict_userdb_iterate_context *)_ctx;
	const char *key, *value;

	if (ctx->iter != NULL && dict_iterate(ctx->iter, &key, &value))
		_ctx->callback(userdb_dict_get_user(ctx, key), _ctx->context);
	else
		_ctx->callback(NULL, _ctx->context);
}

static int userdb_dict_iterate_deinit(struct userdb_iterate_context *_ctx)
{
	struct dict_userdb_iterate_context *ctx =
		(struct dict_userdb_iterate_context *)_ctx;
	int ret = _ctx->failed ? -1 : 0;

	if (ctx->iter != NULL) {
		if (dict_iterate_deinit(&ctx->iter) < 0)
			ret = -1;
	}
	auth_request_unref(&ctx->ctx.auth_request);
	i_free(ctx);
	return ret;
}

static struct userdb_module *
userdb_dict_preinit(pool_t pool, const char *args)
{
	struct dict_userdb_module *module;
	struct dict_connection *conn;

	module = p_new(pool, struct dict_userdb_module, 1);
	module->conn = conn = db_dict_init(args);

	module->module.blocking = TRUE;
	module->module.cache_key =
		auth_cache_parse_key(pool, conn->set.user_key);
	return &module->module;
}

static void userdb_dict_deinit(struct userdb_module *_module)
{
	struct dict_userdb_module *module =
		(struct dict_userdb_module *)_module;

	db_dict_unref(&module->conn);
}

struct userdb_module_interface userdb_dict =
{
	"dict",

	userdb_dict_preinit,
	NULL,
	userdb_dict_deinit,

	userdb_dict_lookup,

	userdb_dict_iterate_init,
	userdb_dict_iterate_next,
	userdb_dict_iterate_deinit
};
