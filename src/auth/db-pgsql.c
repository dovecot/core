/* Copyright (C) 2003 Alex Howansky, Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#if defined(PASSDB_PGSQL) || defined(USERDB_PGSQL)

#include "common.h"
#include "network.h"
#include "str.h"
#include "settings.h"
#include "db-pgsql.h"

#include <stddef.h>
#include <stdlib.h>

#define DEF(type, name) { type, #name, offsetof(struct pgsql_settings, name) }

static struct setting_def setting_defs[] = {
	DEF(SET_STR, connect),
	DEF(SET_STR, password_query),
	DEF(SET_STR, user_query),
	DEF(SET_STR, default_pass_scheme)
};

struct pgsql_settings default_pgsql_settings = {
	MEMBER(connect) "dbname=virtual user=virtual",
	MEMBER(password_query) "SELECT password FROM users WHERE userid = '%u'",
	MEMBER(user_query) "SELECT home, uid, gid FROM users WHERE userid = '%u'",
	MEMBER(default_pass_scheme) "PLAIN-MD5"
};

static struct pgsql_connection *pgsql_connections = NULL;

static int pgsql_conn_open(struct pgsql_connection *conn);
static void pgsql_conn_close(struct pgsql_connection *conn);

const char *db_pgsql_escape(const char *str)
{
	char *esc_str;
	size_t len = strlen(str);

	/* @UNSAFE */
	esc_str = t_malloc(len*2+1);
	PQescapeString(esc_str, str, len);
	return esc_str;
}

void db_pgsql_query(struct pgsql_connection *conn, const char *query,
		    struct pgsql_request *request)
{
	PGresult *res;
	int failed;

	if (!conn->connected) {
		if (!pgsql_conn_open(conn)) {
			request->callback(conn, request, NULL);
			return;
		}
	}

	if (verbose_debug)
		i_info("PGSQL: Performing query: %s", query);
	
	res = PQexec(conn->pg, query);
	switch (PQresultStatus(res)) {
	case PGRES_EMPTY_QUERY:
	case PGRES_COMMAND_OK:
	case PGRES_TUPLES_OK:
		break;

	default:
		/* probably lost connection */
		i_info("PGSQL: Query failed, reconnecting");
		PQclear(res);
		PQreset(conn->pg);

		res = PQexec(conn->pg, query);
		break;
	}

	if (PQresultStatus(res) == PGRES_TUPLES_OK)
		failed = FALSE;
	else {
		i_error("PGSQL: Query \"%s\" failed: %s",
			query, PQresultErrorMessage(res));
		failed = TRUE;
	}

	request->callback(conn, request, failed ? NULL : res);
	PQclear(res);
	i_free(request);
}

static int pgsql_conn_open(struct pgsql_connection *conn)
{
	if (conn->connected)
		return TRUE;

	i_assert(conn->pg == NULL);

	conn->pg = PQconnectdb(conn->set.connect);
	if (PQstatus(conn->pg) != CONNECTION_OK) {
		i_error("PGSQL: Can't connect to database %s",
			conn->set.connect);
		PQfinish(conn->pg);
		conn->pg = NULL;
		return FALSE;
	}

	conn->connected = TRUE;
	return TRUE;
}

static void pgsql_conn_close(struct pgsql_connection *conn)
{
	conn->connected = FALSE;

	if (conn->pg != NULL) {
		PQfinish(conn->pg);
		conn->pg = NULL;
	}
}

static struct pgsql_connection *pgsql_conn_find(const char *config_path)
{
	struct pgsql_connection *conn;

	for (conn = pgsql_connections; conn != NULL; conn = conn->next) {
		if (strcmp(conn->config_path, config_path) == 0)
			return conn;
	}

	return NULL;
}

static const char *parse_setting(const char *key, const char *value,
				 void *context)
{
	struct pgsql_connection *conn = context;

	return parse_setting_from_defs(conn->pool, setting_defs,
				       &conn->set, key, value);
}

struct pgsql_connection *db_pgsql_init(const char *config_path)
{
	struct pgsql_connection *conn;
	pool_t pool;

	conn = pgsql_conn_find(config_path);
	if (conn != NULL) {
		conn->refcount++;
		return conn;
	}

	pool = pool_alloconly_create("pgsql_connection", 1024);
	conn = p_new(pool, struct pgsql_connection, 1);
	conn->pool = pool;

	conn->refcount = 1;

	conn->config_path = p_strdup(pool, config_path);
	conn->set = default_pgsql_settings;
	if (!settings_read(config_path, NULL, parse_setting, NULL, conn))
		exit(FATAL_DEFAULT);

	(void)pgsql_conn_open(conn);

	conn->next = pgsql_connections;
	pgsql_connections = conn;
	return conn;
}

void db_pgsql_unref(struct pgsql_connection *conn)
{
	if (--conn->refcount > 0)
		return;

	pgsql_conn_close(conn);
	pool_unref(conn->pool);
}

#endif
