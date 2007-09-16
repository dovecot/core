/* Copyright (c) 2004-2007 Dovecot authors, see the included COPYING file */

#include "common.h"

#ifdef USERDB_SQL

#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "auth-cache.h"
#include "db-sql.h"
#include "userdb.h"

#include <stdlib.h>
#include <string.h>

struct sql_userdb_module {
	struct userdb_module module;

	struct sql_connection *conn;
};

struct userdb_sql_request {
	struct auth_request *auth_request;
	userdb_callback_t *callback;
};

static void
sql_query_get_result(struct sql_result *result,
		     struct auth_request *auth_request)
{
	const char *name, *value;
	unsigned int i, fields_count;

	auth_request_init_userdb_reply(auth_request);

	fields_count = sql_result_get_fields_count(result);
	for (i = 0; i < fields_count; i++) {
		name = sql_result_get_field_name(result, i);
		value = sql_result_get_field_value(result, i);

		if (*name != '\0' && value != NULL) {
			auth_request_set_userdb_field(auth_request,
						      name, value);
		}
	}
}

static void sql_query_callback(struct sql_result *sql_result,
			       struct userdb_sql_request *sql_request)
{
	struct auth_request *auth_request = sql_request->auth_request;
	enum userdb_result result = USERDB_RESULT_INTERNAL_FAILURE;
	int ret;

	ret = sql_result_next_row(sql_result);
	if (ret < 0) {
		auth_request_log_error(auth_request, "sql",
				       "User query failed: %s",
				       sql_result_get_error(sql_result));
	} else if (ret == 0) {
		result = USERDB_RESULT_USER_UNKNOWN;
		auth_request_log_info(auth_request, "sql", "Unknown user");
	} else {
		sql_query_get_result(sql_result, auth_request);
		result = USERDB_RESULT_OK;
	}

	sql_request->callback(result, auth_request);
	auth_request_unref(&auth_request);
	i_free(sql_request);
}

static const char *
userdb_sql_escape(const char *str, const struct auth_request *auth_request)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct sql_userdb_module *module =
		(struct sql_userdb_module *)_module;

	return sql_escape_string(module->conn->db, str);
}

static void userdb_sql_lookup(struct auth_request *auth_request,
			      userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct sql_userdb_module *module =
		(struct sql_userdb_module *)_module;
	struct userdb_sql_request *sql_request;
	string_t *query;

	query = t_str_new(512);
	var_expand(query, module->conn->set.user_query,
		   auth_request_get_var_expand_table(auth_request,
						     userdb_sql_escape));

	auth_request_ref(auth_request);
	sql_request = i_new(struct userdb_sql_request, 1);
	sql_request->callback = callback;
	sql_request->auth_request = auth_request;

	auth_request_log_debug(auth_request, "sql", "%s", str_c(query));

	sql_query(module->conn->db, str_c(query),
		  sql_query_callback, sql_request);
}

static struct userdb_module *
userdb_sql_preinit(struct auth_userdb *auth_userdb, const char *args)
{
	struct sql_userdb_module *module;

	module = p_new(auth_userdb->auth->pool, struct sql_userdb_module, 1);
	module->conn = db_sql_init(args);

	module->module.cache_key =
		auth_cache_parse_key(auth_userdb->auth->pool,
				     module->conn->set.user_query);
	return &module->module;
}

static void userdb_sql_init(struct userdb_module *_module,
			    const char *args ATTR_UNUSED)
{
	struct sql_userdb_module *module =
		(struct sql_userdb_module *)_module;
	enum sql_db_flags flags;

	flags = sql_get_flags(module->conn->db);
	_module->blocking = (flags & SQL_DB_FLAG_BLOCKING) != 0;

	if (!_module->blocking || worker)
		sql_connect(module->conn->db);
}

static void userdb_sql_deinit(struct userdb_module *_module)
{
	struct sql_userdb_module *module =
		(struct sql_userdb_module *)_module;

	db_sql_unref(&module->conn);
}

struct userdb_module_interface userdb_sql = {
	"sql",

	userdb_sql_preinit,
	userdb_sql_init,
	userdb_sql_deinit,

	userdb_sql_lookup
};

#endif
