/* Copyright (C) 2003 Alex Howansky, Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_MYSQL

#include "common.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "db-mysql.h"
#include "userdb.h"

#include <stdlib.h>
#include <string.h>

struct userdb_mysql_connection {
	struct mysql_connection *conn;
};

struct userdb_mysql_request {
	struct mysql_request request;
	userdb_callback_t *userdb_callback;

	char username[1]; /* variable width */
};

static struct userdb_mysql_connection *userdb_mysql_conn;

static int is_result_valid(MYSQL_RES *res)
{
	int i, n_fields, found;
	MYSQL_FIELD *fields;

	if (res == NULL) {
		i_error("MYSQL: Query failed");
		return FALSE;
	}

	if (mysql_num_rows(res) == 0) {
		if (verbose)
			i_error("MYSQL: Authenticated user not found");
		return FALSE;
	}

	n_fields = mysql_num_fields(res);
	fields = mysql_fetch_fields(res);

	/* Make sure the 'uid' field exists. */
	for (found = 0, i = 0; i < n_fields; i++)
		if (strcmp("uid", fields[i].name) == 0) {
			found = 1;
			break;
		}

	if (!found) {
		i_error("MYSQL: User query did not return 'uid' field");
		return FALSE;
	}

	/* Make sure the 'gid' field exists. */
	for (found = 0, i = 0; i < n_fields; i++)
		if (strcmp("gid", fields[i].name) == 0) {
			found = 1;
			break;
		}

	if (!found) {
		i_error("MYSQL: User query did not return 'gid' field");
		return FALSE;
	}

	return TRUE;
}

static const char *my_get_str(MYSQL_RES *res, MYSQL_ROW row, const char *field)
{
	int i, n_fields;
	unsigned long *lengths;
	MYSQL_FIELD *fields;

	n_fields = mysql_num_fields(res);
	lengths = mysql_fetch_lengths(res);
	fields = mysql_fetch_fields(res);
	for (i = 0; i < n_fields; i++) {
		if (strcmp(field, fields[i].name) == 0)
			return lengths[i] == 0 ? NULL : t_strdup(row[i]);
	}

	return NULL;
}

static void mysql_handle_request(struct mysql_connection *conn __attr_unused__,
				 struct mysql_request *request, MYSQL_RES *res)
{
	struct userdb_mysql_request *urequest =
		(struct userdb_mysql_request *) request;
	struct user_data user;
	MYSQL_ROW row;

	if (res != NULL && is_result_valid(res) &&
	    (row = mysql_fetch_row(res))) {
		memset(&user, 0, sizeof(user));
		user.virtual_user = urequest->username;
		user.system_user = my_get_str(res, row, "system_user");
		user.home = my_get_str(res, row, "home");
		user.mail = my_get_str(res, row, "mail");
		user.uid = atoi(my_get_str(res, row, "uid"));
		user.gid = atoi(my_get_str(res, row, "gid"));
		urequest->userdb_callback(&user, request->context);
	} else {
		urequest->userdb_callback(NULL, request->context);
	}
}

static void userdb_mysql_lookup(struct auth_request *auth_request,
				userdb_callback_t *callback, void *context)
{
	struct mysql_connection *conn = userdb_mysql_conn->conn;
	struct userdb_mysql_request *request;
	const char *query;
	string_t *str;

	str = t_str_new(512);
	var_expand(str, conn->set.user_query,
		   auth_request_get_var_expand_table(auth_request,
						     str_escape));
	query = str_c(str);

	request = i_malloc(sizeof(struct userdb_mysql_request) +
			   strlen(auth_request->user));
	request->request.callback = mysql_handle_request;
	request->request.context = context;
	request->userdb_callback = callback;
	strcpy(request->username, auth_request->user);

	db_mysql_query(conn, query, &request->request);
}

static void userdb_mysql_init(const char *args)
{
	struct mysql_connection *conn;

	userdb_mysql_conn = i_new(struct userdb_mysql_connection, 1);
	userdb_mysql_conn->conn = conn = db_mysql_init(args);
}

static void userdb_mysql_deinit(void)
{
	db_mysql_unref(userdb_mysql_conn->conn);
	i_free(userdb_mysql_conn);
}

struct userdb_module userdb_mysql = {
	userdb_mysql_init,
	userdb_mysql_deinit,

	userdb_mysql_lookup
};

#endif
