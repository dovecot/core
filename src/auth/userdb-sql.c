/* Copyright (C) 2004 Timo Sirainen, Alex Howansky */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_SQL

#include "common.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "db-sql.h"
#include "userdb.h"

#include <stdlib.h>
#include <string.h>

struct userdb_sql_request {
	struct auth_request *auth_request;
	userdb_callback_t *callback;
	void *context;
};

static struct sql_connection *userdb_sql_conn;

static void sql_query_callback(struct sql_result *result, void *context)
{
	struct userdb_sql_request *sql_request = context;
	struct auth_request *auth_request = sql_request->auth_request;
	struct user_data user;
	const char *uid, *gid;
	int ret;

	uid = gid = NULL;
	ret = sql_result_next_row(result);
	if (ret < 0) {
		i_error("sql(%s): User query failed: %s",
			get_log_prefix(auth_request),
			sql_result_get_error(result));
	} else if (ret == 0) {
		if (verbose) {
			i_error("sql(%s): User not found",
				get_log_prefix(auth_request));
		}
	} else {
		uid = sql_result_find_field_value(result, "uid");
		if (uid == NULL) {
			i_error("sql(%s): Password query didn't return uid, "
				"or it was NULL", get_log_prefix(auth_request));
		}
		gid = sql_result_find_field_value(result, "gid");
		if (gid == NULL) {
			i_error("sql(%s): Password query didn't return gid, "
				"or it was NULL", get_log_prefix(auth_request));
		}
	}

	if (uid == NULL || gid == NULL)
		sql_request->callback(NULL, sql_request->context);
	else {
		memset(&user, 0, sizeof(user));
		user.virtual_user = auth_request->user;
		user.system_user =
			sql_result_find_field_value(result, "system_user");
		user.home = sql_result_find_field_value(result, "home");
		user.mail = sql_result_find_field_value(result, "mail");

		user.uid = userdb_parse_uid(auth_request, uid);
		user.gid = userdb_parse_gid(auth_request, uid);
		if (user.uid == (uid_t)-1 || user.gid == (gid_t)-1)
			sql_request->callback(NULL, sql_request->context);
		else
			sql_request->callback(&user, sql_request->context);
	}
	i_free(sql_request);
}

static void userdb_sql_lookup(struct auth_request *auth_request,
			      userdb_callback_t *callback, void *context)
{
	struct userdb_sql_request *sql_request;
	string_t *query;

	query = t_str_new(512);
	var_expand(query, userdb_sql_conn->set.user_query,
		   auth_request_get_var_expand_table(auth_request,
						     str_escape));

	sql_request = i_new(struct userdb_sql_request, 1);
	sql_request->callback = callback;
	sql_request->context = context;
	sql_request->auth_request = auth_request;

	if (verbose_debug) {
		i_info("sql(%s): query: %s",
		       get_log_prefix(auth_request), str_c(query));
	}

	sql_query(userdb_sql_conn->db, str_c(query),
		  sql_query_callback, sql_request);
}

static void userdb_sql_preinit(const char *args)
{
	userdb_sql_conn = db_sql_init(args);
}

static void userdb_sql_init(const char *args __attr_unused__)
{
	db_sql_connect(userdb_sql_conn);
}

static void userdb_sql_deinit(void)
{
	db_sql_unref(userdb_sql_conn);
}

struct userdb_module userdb_sql = {
	"sql",

	userdb_sql_preinit,
	userdb_sql_init,
	userdb_sql_deinit,

	userdb_sql_lookup
};

#endif
