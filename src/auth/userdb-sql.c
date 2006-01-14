/* Copyright (C) 2004 Timo Sirainen, Alex Howansky */

#include "common.h"

#ifdef USERDB_SQL

#include "str.h"
#include "strescape.h"
#include "var-expand.h"
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

static struct auth_stream_reply *
sql_query_get_result(struct sql_result *result,
		     struct auth_request *auth_request)
{
	struct auth_stream_reply *reply;
	uid_t uid, gid;
	const char *name, *value;
	unsigned int i, fields_count;

	uid = (uid_t)-1;
	gid = (gid_t)-1;

	reply = auth_stream_reply_init(auth_request);
	auth_stream_reply_add(reply, NULL, auth_request->user);

	fields_count = sql_result_get_fields_count(result);
	for (i = 0; i < fields_count; i++) {
		name = sql_result_get_field_name(result, i);
		value = sql_result_get_field_value(result, i);

		if (value == NULL)
			continue;

		/* some special handling for UID and GID. */
		if (strcmp(name, "uid") == 0) {
			uid = userdb_parse_uid(auth_request, value);
			if (uid == (uid_t)-1)
				return NULL;
			value = dec2str(uid);
		} else if (strcmp(name, "gid") == 0) {
			gid = userdb_parse_gid(auth_request, value);
			if (gid == (gid_t)-1)
				return NULL;
			value = dec2str(gid);
		}

		auth_stream_reply_add(reply, name, value);
	}

	if (uid == (uid_t)-1) {
		auth_request_log_error(auth_request, "sql",
			"Password query didn't return uid, or it was NULL");
		return NULL;
	}
	if (gid == (gid_t)-1) {
		auth_request_log_error(auth_request, "sql",
			"Password query didn't return gid, or it was NULL");
		return NULL;
	}

	return reply;
}

static void sql_query_callback(struct sql_result *result, void *context)
{
	struct userdb_sql_request *sql_request = context;
	struct auth_request *auth_request = sql_request->auth_request;
	struct auth_stream_reply *reply = NULL;
	int ret;

	ret = sql_result_next_row(result);
	if (ret < 0) {
		auth_request_log_error(auth_request, "sql",
			"User query failed: %s", sql_result_get_error(result));
	} else if (ret == 0) {
		auth_request_log_info(auth_request, "sql", "User not found");
	} else {
                reply = sql_query_get_result(result, auth_request);
	}

	sql_request->callback(reply, auth_request);
	auth_request_unref(&auth_request);
	i_free(sql_request);
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
						     str_escape));

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
	return &module->module;
}

static void userdb_sql_init(struct userdb_module *_module,
			    const char *args __attr_unused__)
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
