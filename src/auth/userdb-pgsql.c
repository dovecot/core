/* Copyright (C) 2003 Alex Howansky, Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_PGSQL

#include "common.h"
#include "str.h"
#include "var-expand.h"
#include "db-pgsql.h"
#include "userdb.h"

#include <libpq-fe.h>
#include <stdlib.h>
#include <string.h>

struct userdb_pgsql_connection {
	struct pgsql_connection *conn;
};

struct userdb_pgsql_request {
	struct pgsql_request request;
	userdb_callback_t *userdb_callback;
};

static struct userdb_pgsql_connection *userdb_pgsql_conn;

static int is_result_valid(PGresult *res)
{
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		i_error("PGSQL: Query failed");
		return FALSE;
	}

	if (PQntuples(res) == 0) {
		if (verbose)
			i_error("PGSQL: Authenticated user not found");
		return FALSE;
	}

	if (PQfnumber(res, "home") == -1) {
		i_error("PGSQL: User query did not return 'home' field");
		return FALSE;
	}

	if (PQfnumber(res, "uid") == -1) {
		i_error("PGSQL: User query did not return 'uid' field");
		return FALSE;
	}

	if (PQfnumber(res, "gid") == -1) {
		i_error("PGSQL: User query did not return 'gid' field");
		return FALSE;
	}

	return TRUE;
}

static void pgsql_handle_request(struct pgsql_connection *conn __attr_unused__,
				 struct pgsql_request *request, PGresult *res)
{
	struct userdb_pgsql_request *urequest =
		(struct userdb_pgsql_request *) request;
	struct user_data user;

	if (res != NULL && is_result_valid(res)) {
		memset(&user, 0, sizeof(user));
		user.home = PQgetvalue(res, 0, PQfnumber(res, "home"));
		user.uid = atoi(PQgetvalue(res, 0, PQfnumber(res, "uid")));
		user.gid = atoi(PQgetvalue(res, 0, PQfnumber(res, "gid")));
		urequest->userdb_callback(&user, request->context);
	} else {
		urequest->userdb_callback(NULL, request->context);
	}
}

static void userdb_pgsql_lookup(const char *user, userdb_callback_t *callback,
				void *context)
{
	struct pgsql_connection *conn = userdb_pgsql_conn->conn;
	struct userdb_pgsql_request *request;
	const char *query;
	string_t *str;

	str = t_str_new(512);
	var_expand(str, conn->set.user_query, user, NULL);
	query = str_c(str);

	request = i_new(struct userdb_pgsql_request, 1);
	request->request.callback = pgsql_handle_request;
	request->request.context = context;
	request->userdb_callback = callback;

	if (db_pgsql_is_valid_username(conn, user))
		db_pgsql_query(conn, query, &request->request);
	else {
		if (verbose)
			i_info("pgsql(%s): Invalid username", user);
		pgsql_handle_request(conn, &request->request, NULL);
	}
}

static void userdb_pgsql_init(const char *args)
{
	struct pgsql_connection *conn;

	userdb_pgsql_conn = i_new(struct userdb_pgsql_connection, 1);
	userdb_pgsql_conn->conn = conn = db_pgsql_init(args);
}

static void userdb_pgsql_deinit(void)
{
	db_pgsql_unref(userdb_pgsql_conn->conn);
	i_free(userdb_pgsql_conn);
}

struct userdb_module userdb_pgsql = {
	userdb_pgsql_init,
	userdb_pgsql_deinit,

	userdb_pgsql_lookup
};

#endif
