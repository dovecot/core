/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_SQL

#include "safe-memset.h"
#include "settings.h"
#include "settings-parser.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "db-sql.h"

#include <string.h>

struct sql_passdb_module {
	struct passdb_module module;

	struct sql_db *db;
};

struct passdb_sql_request {
	struct auth_request *auth_request;
	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
		set_credentials_callback_t *set_credentials;
	} callback;
};

struct passdb_sql_settings {
	pool_t pool;
	const char *query;
	const char *update_query;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("passdb_sql_"#name, name, struct passdb_sql_settings)
static const struct setting_define passdb_sql_setting_defines[] = {
	DEF(STR, query),
	DEF(STR, update_query),

	SETTING_DEFINE_LIST_END
};

static const struct passdb_sql_settings passdb_sql_default_settings = {
	.query = "",
	.update_query = "",
};
const struct setting_parser_info passdb_sql_setting_parser_info = {
	.name = "passdb_sql",

	.defines = passdb_sql_setting_defines,
	.defaults = &passdb_sql_default_settings,

	.struct_size = sizeof(struct passdb_sql_settings),
	.pool_offset1 = 1 + offsetof(struct passdb_sql_settings, pool),
};

static int sql_query_save_results(struct sql_result *result,
				  struct passdb_sql_request *sql_request)
{
	struct auth_request *auth_request = sql_request->auth_request;
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct auth_fields *fields = auth_fields_init(auth_request->pool);
	unsigned int i, fields_count;
	const char *name, *value;

        fields_count = sql_result_get_fields_count(result);
	for (i = 0; i < fields_count; i++) {
		name = sql_result_get_field_name(result, i);
		value = sql_result_get_field_value(result, i);

		if (*name == '\0')
			continue;

		auth_fields_add(fields, name, value, 0);
		if (!auth_request->passdb->set->fields_import_all)
			;
		else if (value == NULL)
			auth_request_set_null_field(auth_request, name);
		else {
			auth_request_set_field(auth_request, name, value,
				_module->default_pass_scheme);
		}
	}
	return auth_request_set_passdb_fields(auth_request, fields);
}

static void sql_query_callback(struct sql_result *result,
			       struct passdb_sql_request *sql_request)
{
	struct auth_request *auth_request = sql_request->auth_request;
	enum passdb_result passdb_result;
	const char *password, *scheme;
	char *dup_password = NULL;
	int ret;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	password = NULL;

	ret = sql_result_next_row(result);
	if (ret >= 0)
		db_sql_success();
	if (ret < 0) {
		e_error(authdb_event(auth_request), "Password query failed: %s",
			sql_result_get_error(result));
	} else if (ret == 0) {
		auth_request_db_log_unknown_user(auth_request);
		passdb_result = PASSDB_RESULT_USER_UNKNOWN;
	} else if (sql_query_save_results(result, sql_request) < 0)
		;
	else {
		/* Note that we really want to check if the password field is
		   found. Just checking if password is set isn't enough,
		   because with proxies we might want to return NULL as
		   password. */
		if (sql_result_find_field(result, "password") < 0 &&
		    sql_result_find_field(result, "password_noscheme") < 0) {
			e_error(authdb_event(auth_request),
				"Password query must return a field named "
				"'password'");
		} else if (sql_result_next_row(result) > 0) {
			e_error(authdb_event(auth_request),
				"Password query returned multiple matches");
		} else if (auth_request->passdb_password == NULL &&
			   !auth_fields_exists(auth_request->fields.extra_fields,
					       "nopassword")) {
			passdb_result = auth_request_password_missing(auth_request);
		} else {
			/* passdb_password may change on the way,
			   so we'll need to strdup. */
			dup_password = t_strdup_noconst(auth_request->passdb_password);
			password = dup_password;
			passdb_result = PASSDB_RESULT_OK;
		}
	}

	scheme = password_get_scheme(&password);
	/* auth_request_set_field() sets scheme */
	i_assert(password == NULL || scheme != NULL);

	if (auth_request->wanted_credentials_scheme != NULL) {
		passdb_handle_credentials(passdb_result, password, scheme,
			sql_request->callback.lookup_credentials,
			auth_request);
		if (dup_password != NULL)
			safe_memset(dup_password, 0, strlen(dup_password));
		auth_request_unref(&auth_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		sql_request->callback.verify_plain(passdb_result, auth_request);
		auth_request_unref(&auth_request);
		return;
	}

	passdb_result = auth_request_db_password_verify(
		auth_request, auth_request->mech_password, password, scheme);

	sql_request->callback.verify_plain(passdb_result, auth_request);
	i_assert(dup_password != NULL);
	safe_memset(dup_password, 0, strlen(dup_password));
	auth_request_unref(&auth_request);
}

static const char *passdb_sql_escape(const char *str, void *context)
{
	struct sql_db *db = context;
	return sql_escape_string(db, str);
}

static void sql_lookup_pass(struct passdb_sql_request *sql_request)
{
	struct passdb_module *_module =
		sql_request->auth_request->passdb->passdb;
	struct sql_passdb_module *module =
		container_of(_module, struct sql_passdb_module, module);
	const struct passdb_sql_settings *set;
	const char *error;

	struct settings_get_params params = {
		.escape_func = passdb_sql_escape,
		.escape_context = module->db,
	};
	if (settings_get_params(authdb_event(sql_request->auth_request),
				&passdb_sql_setting_parser_info, &params,
				&set, &error) < 0) {
		e_error(authdb_event(sql_request->auth_request), "%s", error);
		sql_request->callback.verify_plain(
			PASSDB_RESULT_INTERNAL_FAILURE,
			sql_request->auth_request);
		return;
	}

	e_debug(authdb_event(sql_request->auth_request),
		"query: %s", set->query);

	auth_request_ref(sql_request->auth_request);
	sql_query(module->db, set->query, sql_query_callback, sql_request);
	settings_free(set);
}

static void sql_verify_plain(struct auth_request *request,
			     const char *password ATTR_UNUSED,
			     verify_plain_callback_t *callback)
{
	struct passdb_sql_request *sql_request;

	sql_request = p_new(request->pool, struct passdb_sql_request, 1);
	sql_request->auth_request = request;
	sql_request->callback.verify_plain = callback;

	sql_lookup_pass(sql_request);
}

static void sql_lookup_credentials(struct auth_request *request,
				   lookup_credentials_callback_t *callback)
{
	struct passdb_sql_request *sql_request;

	sql_request = p_new(request->pool, struct passdb_sql_request, 1);
	sql_request->auth_request = request;
	sql_request->callback.lookup_credentials = callback;

        sql_lookup_pass(sql_request);
}

static void sql_set_credentials_callback(const struct sql_commit_result *sql_result,
					 struct passdb_sql_request *sql_request)
{
	struct auth_request *auth_request = sql_request->auth_request;

	if (sql_result->error != NULL) {
		e_error(authdb_event(auth_request),
			"Set credentials query failed: %s", sql_result->error);
	}

	sql_request->callback.
		set_credentials(sql_result->error == NULL, sql_request->auth_request);
	i_free(sql_request);
}

static void sql_set_credentials(struct auth_request *request,
				const char *new_credentials,
				set_credentials_callback_t *callback)
{
	struct sql_passdb_module *module =
		container_of(request->passdb->passdb,
			     struct sql_passdb_module, module);
	struct sql_transaction_context *transaction;
	struct passdb_sql_request *sql_request;
	const struct passdb_sql_settings *set;
	const char *error;

	request->mech_password = p_strdup(request->pool, new_credentials);

	if (settings_get(authdb_event(request), &passdb_sql_setting_parser_info, 0,
			 &set, &error) < 0) {
		e_error(authdb_event(request), "%s", error);
		callback(FALSE, request);
		return;
	}

	sql_request = i_new(struct passdb_sql_request, 1);
	sql_request->auth_request = request;
	sql_request->callback.set_credentials = callback;

	transaction = sql_transaction_begin(module->db);
	sql_update(transaction, set->update_query);
	sql_transaction_commit(&transaction,
			       sql_set_credentials_callback, sql_request);
	settings_free(set);
}

static int
passdb_sql_preinit(pool_t pool, struct event *event,
		   struct passdb_module **module_r, const char **error_r)
{
	struct sql_passdb_module *module;
	const struct passdb_sql_settings *set;
	const struct auth_passdb_post_settings *post_set;

	if (settings_get(event, &passdb_sql_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_CHECK |
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &set, error_r) < 0)
		return -1;
	if (settings_get(event, &auth_passdb_post_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_CHECK |
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &post_set, error_r) < 0) {
		settings_free(set);
		return -1;
	}

	module = p_new(pool, struct sql_passdb_module, 1);
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

static void passdb_sql_init(struct passdb_module *_module)
{
	struct sql_passdb_module *module =
		container_of(_module, struct sql_passdb_module, module);
	enum sql_db_flags flags;

	flags = sql_get_flags(module->db);
	if (!module->module.blocking)
		module->module.blocking = (flags & SQL_DB_FLAG_BLOCKING) != 0;

	if (!module->module.blocking || worker)
		db_sql_connect(module->db);
}

static void passdb_sql_deinit(struct passdb_module *_module)
{
	struct sql_passdb_module *module =
		container_of(_module, struct sql_passdb_module, module);

	/* Abort any pending requests, even if the database is still
	   kept referenced. */
	sql_disconnect(module->db);
	sql_unref(&module->db);
}

struct passdb_module_interface passdb_sql = {
	.name = "sql",

	.preinit = passdb_sql_preinit,
	.init = passdb_sql_init,
	.deinit = passdb_sql_deinit,

	.verify_plain = sql_verify_plain,
	.lookup_credentials = sql_lookup_credentials,
	.set_credentials = sql_set_credentials
};
#else
struct passdb_module_interface passdb_sql = {
	.name = "sql"
};
#endif
