/* Copyright (C) 2003 Alex Howansky, Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#if defined(PASSDB_MYSQL) || defined(USERDB_MYSQL)
#include "common.h"
#include "network.h"
#include "str.h"
#include "settings.h"
#include "db-mysql.h"

#include <limits.h>
#include <stddef.h>
#include <stdlib.h>

#define DEF(type, name) { type, #name, offsetof(struct mysql_settings, name) }

static struct setting_def setting_defs[] = {
	DEF(SET_STR, db_host),
	DEF(SET_INT, db_port),
	DEF(SET_STR, db_unix_socket),
	DEF(SET_STR, db),
	DEF(SET_STR, db_user),
	DEF(SET_STR, db_passwd),
	DEF(SET_INT, db_client_flags),
	DEF(SET_STR, ssl_key),
	DEF(SET_STR, ssl_cert),
	DEF(SET_STR, ssl_ca),
	DEF(SET_STR, ssl_ca_path),
	DEF(SET_STR, ssl_cipher),
	DEF(SET_STR, password_query),
	DEF(SET_STR, user_query),
	DEF(SET_STR, default_pass_scheme)
};

struct mysql_settings default_mysql_settings = {
	MEMBER(db_host) "localhost",
	MEMBER(db_port) 0,
	MEMBER(db_unix_socket) NULL,
	MEMBER(db) NULL,
	MEMBER(db_user) NULL,
	MEMBER(db_passwd) NULL,
	MEMBER(db_client_flags) 0,
	MEMBER(ssl_key) NULL,
	MEMBER(ssl_cert) NULL,
	MEMBER(ssl_ca) NULL,
	MEMBER(ssl_ca_path) NULL,
	MEMBER(ssl_cipher) "HIGH",
	MEMBER(password_query) "SELECT password FROM users WHERE userid = '%u'",
	MEMBER(user_query) "SELECT home, uid, gid FROM users WHERE userid = '%u'",
	MEMBER(default_pass_scheme) "PLAIN-MD5"
};

static struct mysql_connection *mysql_connections = NULL;

static int mysql_conn_open(struct mysql_connection *conn);
static void mysql_conn_close(struct mysql_connection *conn);

void db_mysql_query(struct mysql_connection *conn, const char *query,
		    struct mysql_request *request)
{
	MYSQL_RES *res = NULL;
	int failed;

	if (verbose_debug)
		i_info("MySQL: Performing query: %s", query);

	if (!conn->connected) {
		if (!mysql_conn_open(conn)) {
			request->callback(conn, request, NULL);
			return;
		}
	}

	failed = mysql_query(conn->mysql, query) != 0;
	if (failed) {
		/* query failed */
		switch (mysql_errno(conn->mysql)) {
		case CR_SERVER_GONE_ERROR:
		case CR_SERVER_LOST:
			/* connection lost - try immediate reconnect */
			if (!mysql_conn_open(conn))
				break;
			if (mysql_query(conn->mysql, query) == 0) {
				failed = FALSE;
				break;
			}
			/* query failed, fallback to error handler */
		default:
			i_error("MySQL: Error executing query \"%s\": %s",
				query, mysql_error(conn->mysql));
			break;
		}
	}

	if (!failed) {
		/* query succeeded */
		if ((res = mysql_store_result(conn->mysql)) == NULL) {
			/* something went wrong on storing result */
			failed = TRUE;
			i_error("MySQL: Error retrieving results: %s",
				mysql_error(conn->mysql));
		}
	}

	request->callback(conn, request, res);
	if (!failed)
		mysql_free_result(res);
	i_free(request);
}

static int mysql_conn_open(struct mysql_connection *conn)
{
	int use_ssl = FALSE;

	if (conn->connected)
		return TRUE;

	if (conn->mysql == NULL) {
		conn->mysql = mysql_init(NULL);
		if (conn->mysql == NULL) {
			i_error("MySQL: mysql_init failed");
			return FALSE;
		}
	}

#ifdef HAVE_MYSQL_SSL
	if (conn->set.ssl_ca != NULL || conn->set.ssl_ca_path != NULL) {
		mysql_ssl_set(conn->mysql, conn->set.ssl_key,
			      conn->set.ssl_cert,
			      conn->set.ssl_ca,
			      conn->set.ssl_ca_path
#ifdef HAVE_MYSQL_SSL_CIPHER
			      ,conn->set.ssl_cipher
#endif
			     );
		use_ssl = TRUE;
	}
#endif

	if (mysql_real_connect(conn->mysql, conn->set.db_host,
			       conn->set.db_user, conn->set.db_passwd,
			       conn->set.db,
			       conn->set.db_port,
			       conn->set.db_unix_socket,
			       conn->set.db_client_flags) == NULL) {
		i_error("MySQL: Can't connect to database %s: %s",
			conn->set.db, mysql_error(conn->mysql));
	} else {
		conn->connected = TRUE;
		i_info("MySQL: connected to %s%s", conn->set.db_host,
		       use_ssl ? "using SSL" : "");
	}
	
	return conn->connected;
}

static void mysql_conn_close(struct mysql_connection *conn)
{
	conn->connected = FALSE;

	if (conn->mysql != NULL) {
		mysql_close(conn->mysql);
		conn->mysql = NULL;
	}
}

static struct mysql_connection *mysql_conn_find(const char *config_path)
{
	struct mysql_connection *conn;

	for (conn = mysql_connections; conn != NULL; conn = conn->next) {
		if (strcmp(conn->config_path, config_path) == 0)
			return conn;
	}

	return NULL;
}

static const char *parse_setting(const char *key, const char *value,
				 void *context)
{
	struct mysql_connection *conn = context;

	return parse_setting_from_defs(conn->pool, setting_defs,
				       &conn->set, key, value);
}

struct mysql_connection *db_mysql_init(const char *config_path)
{
	struct mysql_connection *conn;
	pool_t pool;

	conn = mysql_conn_find(config_path);
	if (conn != NULL) {
		conn->refcount++;
		return conn;
	}

	pool = pool_alloconly_create("mysql_connection", 1024);
	conn = p_new(pool, struct mysql_connection, 1);
	conn->pool = pool;

	conn->refcount = 1;

	conn->config_path = p_strdup(pool, config_path);
	conn->set = default_mysql_settings;
	if (!settings_read(config_path, NULL, parse_setting, NULL, conn))
		exit(FATAL_DEFAULT);

	if (conn->set.db == NULL)
		i_fatal("MySQL: db variable isn't set in config file");
	if (conn->set.db_user == NULL)
		i_fatal("MySQL: db_user variable isn't set in config file");

	(void)mysql_conn_open(conn);

	conn->next = mysql_connections;
	mysql_connections = conn;
	return conn;
}

void db_mysql_unref(struct mysql_connection *conn)
{
	if (--conn->refcount > 0)
		return;

	mysql_conn_close(conn);
	pool_unref(conn->pool);
}

#endif
