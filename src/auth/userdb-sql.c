/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"

#ifdef USERDB_SQL

#include "settings.h"
#include "settings-parser.h"
#include "auth-cache.h"
#include "db-sql.h"

#include <string.h>

struct sql_userdb_module {
	struct userdb_module module;

	struct sql_db *db;
};

struct userdb_sql_request {
	struct auth_request *auth_request;
	userdb_callback_t *callback;
};

struct sql_userdb_iterate_context {
	struct userdb_iterate_context ctx;
	struct sql_result *result;
	bool query_sent:1;
	bool freed:1;
	bool call_iter:1;
};

struct userdb_sql_settings {
	pool_t pool;
	const char *query;
	const char *iterate_query;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("userdb_sql_"#name, name, struct userdb_sql_settings)
static const struct setting_define userdb_sql_setting_defines[] = {
	DEF(STR, query),
	DEF(STR, iterate_query),

	SETTING_DEFINE_LIST_END
};
static const struct userdb_sql_settings userdb_sql_default_settings = {
	.query = "",
	.iterate_query = "",
};
const struct setting_parser_info userdb_sql_setting_parser_info = {
	.name = "userdb_sql",

	.defines = userdb_sql_setting_defines,
	.defaults = &userdb_sql_default_settings,

	.struct_size = sizeof(struct userdb_sql_settings),
	.pool_offset1 = 1 + offsetof(struct userdb_sql_settings, pool),
};

static void userdb_sql_iterate_next(struct userdb_iterate_context *_ctx);
static int userdb_sql_iterate_deinit(struct userdb_iterate_context *_ctx);

static int
sql_query_get_result(struct sql_result *result,
		     struct auth_request *auth_request)
{
	struct auth_fields *fields = auth_fields_init(auth_request->pool);
	const char *name, *value;
	unsigned int i, fields_count;

	fields_count = sql_result_get_fields_count(result);
	for (i = 0; i < fields_count; i++) {
		name = sql_result_get_field_name(result, i);
		value = sql_result_get_field_value(result, i);

		if (*name == '\0' || value == NULL)
			continue;

		auth_fields_add(fields, name, value, 0);
		if (auth_request->userdb->set->fields_import_all) {
			auth_request_set_userdb_field(auth_request,
						      name, value);
		}
	}
	return auth_request_set_userdb_fields(auth_request, fields);
}

static void sql_query_callback(struct sql_result *sql_result,
			       struct userdb_sql_request *sql_request)
{
	struct auth_request *auth_request = sql_request->auth_request;
	enum userdb_result result = USERDB_RESULT_INTERNAL_FAILURE;
	int ret;

	ret = sql_result_next_row(sql_result);
	if (ret >= 0)
		db_sql_success();
	if (ret < 0) {
		e_error(authdb_event(auth_request), "User query failed: %s",
			sql_result_get_error(sql_result));
	} else if (ret == 0) {
		result = USERDB_RESULT_USER_UNKNOWN;
		auth_request_db_log_unknown_user(auth_request);
	} else if (sql_query_get_result(sql_result, auth_request) == 0) {
		result = USERDB_RESULT_OK;
	}

	sql_request->callback(result, auth_request);
	auth_request_unref(&auth_request);
	i_free(sql_request);
}

static const char *userdb_sql_escape(const char *str, void *context)
{
	struct sql_db *db = context;
	return sql_escape_string(db, str);
}

static void userdb_sql_lookup(struct auth_request *auth_request,
			      userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct sql_userdb_module *module =
		container_of(_module, struct sql_userdb_module, module);
	struct userdb_sql_request *sql_request;
	const struct userdb_sql_settings *set;
	const char *error;

	struct settings_get_params params = {
		.escape_func = userdb_sql_escape,
		.escape_context = module->db,
	};
	if (settings_get_params(authdb_event(auth_request),
				&userdb_sql_setting_parser_info, &params,
				&set, &error) < 0) {
		e_error(authdb_event(auth_request), "%s", error);
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	}

	auth_request_ref(auth_request);
	sql_request = i_new(struct userdb_sql_request, 1);
	sql_request->callback = callback;
	sql_request->auth_request = auth_request;

	e_debug(authdb_event(auth_request), "%s", set->query);

	sql_query(module->db, set->query, sql_query_callback, sql_request);
	settings_free(set);
}

static void sql_iter_query_callback(struct sql_result *sql_result,
				    struct sql_userdb_iterate_context *ctx)
{
	ctx->result = sql_result;
	sql_result_ref(sql_result);

	if (ctx->freed)
		(void)userdb_sql_iterate_deinit(&ctx->ctx);
	else if (ctx->call_iter)
		userdb_sql_iterate_next(&ctx->ctx);
}

static struct userdb_iterate_context *
userdb_sql_iterate_init(struct auth_request *auth_request,
			userdb_iter_callback_t *callback, void *context)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct sql_userdb_module *module =
		container_of(_module, struct sql_userdb_module, module);
	struct sql_userdb_iterate_context *ctx;
	const struct userdb_sql_settings *set;
	const char *error;

	ctx = i_new(struct sql_userdb_iterate_context, 1);
	ctx->ctx.auth_request = auth_request;
	ctx->ctx.callback = callback;
	ctx->ctx.context = context;
	auth_request_ref(auth_request);

	if (settings_get(authdb_event(auth_request),
			 &userdb_sql_setting_parser_info, 0,
			 &set, &error) < 0) {
		e_error(authdb_event(auth_request), "%s", error);
		ctx->ctx.failed = TRUE;
		return &ctx->ctx;
	}

	if (*set->iterate_query == '\0') {
		e_error(authdb_event(auth_request), "User iteration failed: "
			"userdb_sql_iterate_query is empty");
		ctx->ctx.failed = TRUE;
	} else {
		ctx->query_sent = TRUE;
		sql_query(module->db, set->iterate_query, sql_iter_query_callback, ctx);
		e_debug(authdb_event(auth_request), "%s", set->iterate_query);
	}
	settings_free(set);
	return &ctx->ctx;
}

static int userdb_sql_iterate_get_user(struct sql_userdb_iterate_context *ctx,
				       const char **user_r)
{
	const char *domain;
	int idx;

	/* try user first */
	idx = sql_result_find_field(ctx->result, "user");
	if (idx == 0) {
		*user_r = sql_result_get_field_value(ctx->result, idx);
		return 0;
	}

	/* username [+ domain]? */
	idx = sql_result_find_field(ctx->result, "username");
	if (idx < 0) {
		/* no user or username, fail */
		return -1;
	}

	*user_r = sql_result_get_field_value(ctx->result, idx);
	if (*user_r == NULL)
		return 0;

	domain = sql_result_find_field_value(ctx->result, "domain");
	if (domain != NULL)
		*user_r = t_strconcat(*user_r, "@", domain, NULL);
	return 0;
}

static void userdb_sql_iterate_next(struct userdb_iterate_context *_ctx)
{
	struct sql_userdb_iterate_context *ctx =
		container_of(_ctx, struct sql_userdb_iterate_context, ctx);
	const char *user;
	int ret;

	if (_ctx->failed) {
		_ctx->callback(NULL, _ctx->context);
		return;
	}
	if (ctx->result == NULL) {
		/* query not finished yet */
		ctx->call_iter = TRUE;
		return;
	}

	ret = sql_result_next_row(ctx->result);
	if (ret >= 0)
		db_sql_success();
	if (ret > 0) {
		if (userdb_sql_iterate_get_user(ctx, &user) < 0)
			e_error(authdb_event(_ctx->auth_request),
				"sql: Iterate query didn't return 'user' field");
		else if (user == NULL)
			e_error(authdb_event(_ctx->auth_request),
				"sql: Iterate query returned NULL user");
		else {
			_ctx->callback(user, _ctx->context);
			return;
		}
		_ctx->failed = TRUE;
	} else if (ret < 0) {
		e_error(authdb_event(_ctx->auth_request),
			"sql: Iterate query failed: %s",
			sql_result_get_error(ctx->result));
		_ctx->failed = TRUE;
	}
	_ctx->callback(NULL, _ctx->context);
}

static int userdb_sql_iterate_deinit(struct userdb_iterate_context *_ctx)
{
	struct sql_userdb_iterate_context *ctx =
		container_of(_ctx, struct sql_userdb_iterate_context, ctx);
	int ret = _ctx->failed ? -1 : 0;

	auth_request_unref(&_ctx->auth_request);
	if (ctx->query_sent && ctx->result == NULL) {
		/* sql query hasn't finished yet */
		ctx->freed = TRUE;
	} else {
		if (ctx->result != NULL)
			sql_result_unref(ctx->result);
		i_free(ctx);
	}
	return ret;
}

static int
userdb_sql_preinit(pool_t pool, struct event *event,
		   struct userdb_module **module_r, const char **error_r)
{
	struct sql_userdb_module *module;
	const struct userdb_sql_settings *set;
	const struct auth_userdb_post_settings *post_set;

	if (settings_get(event, &userdb_sql_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_CHECK |
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &set, error_r) < 0)
		return -1;
	if (settings_get(event, &auth_userdb_post_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_CHECK |
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &post_set, error_r) < 0) {
		settings_free(set);
		return -1;
	}

	module = p_new(pool, struct sql_userdb_module, 1);
	if (sql_init_auto(event, &module->db, error_r) <= 0) {
		settings_free(set);
		settings_free(post_set);
		return -1;
	}

	module->module.default_cache_key =
		auth_cache_parse_key_and_fields(pool, set->query,
						&post_set->fields, "sql");
	settings_free(set);
	settings_free(post_set);
	*module_r = &module->module;
	return 0;
}

static void userdb_sql_init(struct userdb_module *_module)
{
	struct sql_userdb_module *module =
		container_of(_module, struct sql_userdb_module, module);
	enum sql_db_flags flags;

	flags = sql_get_flags(module->db);
	if (!_module->blocking)
		_module->blocking = (flags & SQL_DB_FLAG_BLOCKING) != 0;

	if (!_module->blocking || worker)
		db_sql_connect(module->db);
}

static void userdb_sql_deinit(struct userdb_module *_module)
{
	struct sql_userdb_module *module =
		container_of(_module, struct sql_userdb_module, module);

	/* Abort any pending requests, even if the database is still
	   kept referenced. */
	sql_disconnect(module->db);
	sql_unref(&module->db);
}

struct userdb_module_interface userdb_sql = {
	.name = "sql",

	.preinit = userdb_sql_preinit,
	.init = userdb_sql_init,
	.deinit = userdb_sql_deinit,

	.lookup = userdb_sql_lookup,

	.iterate_init = userdb_sql_iterate_init,
	.iterate_next = userdb_sql_iterate_next,
	.iterate_deinit = userdb_sql_iterate_deinit
};
#else
struct userdb_module_interface userdb_sql = {
	.name = "sql"
};
#endif
