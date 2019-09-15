/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#if defined(PASSDB_SQL) || defined(USERDB_SQL)

#include "settings.h"
#include "auth-request.h"
#include "auth-worker-client.h"
#include "db-sql.h"

#include <stddef.h>

#define DEF_STR(name) DEF_STRUCT_STR(name, db_sql_settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, db_sql_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, db_sql_settings)

static struct setting_def setting_defs[] = {
	DEF_STR(driver),
	DEF_STR(connect),
	DEF_STR(password_query),
	DEF_STR(user_query),
 	DEF_STR(update_query),
 	DEF_STR(iterate_query),
	DEF_STR(default_pass_scheme),
	DEF_BOOL(userdb_warning_disable),

	{ 0, NULL, 0 }
};

static struct db_sql_settings default_db_sql_settings = {
	.driver = NULL,
	.connect = NULL,
	.password_query = "SELECT username, domain, password FROM users WHERE username = '%n' AND domain = '%d'",
	.user_query = "SELECT home, uid, gid FROM users WHERE username = '%n' AND domain = '%d'",
	.update_query = "UPDATE users SET password = '%w' WHERE username = '%n' AND domain = '%d'",
	.iterate_query = "SELECT username, domain FROM users",
	.default_pass_scheme = "MD5",
	.userdb_warning_disable = FALSE
};

static struct db_sql_connection *connections = NULL;

static struct db_sql_connection *sql_conn_find(const char *config_path)
{
	struct db_sql_connection *conn;

	for (conn = connections; conn != NULL; conn = conn->next) {
		if (strcmp(conn->config_path, config_path) == 0)
			return conn;
	}

	return NULL;
}

static const char *parse_setting(const char *key, const char *value,
				 struct db_sql_connection *conn)
{
	return parse_setting_from_defs(conn->pool, setting_defs,
				       &conn->set, key, value);
}

struct db_sql_connection *db_sql_init(const char *config_path, bool userdb)
{
	struct db_sql_connection *conn;
	struct sql_settings set;
	const char *error;
	pool_t pool;

	conn = sql_conn_find(config_path);
	if (conn != NULL) {
		if (userdb)
			conn->userdb_used = TRUE;
		conn->refcount++;
		return conn;
	}

	if (*config_path == '\0')
		i_fatal("sql: Configuration file path not given");

	pool = pool_alloconly_create("db_sql_connection", 1024);
	conn = p_new(pool, struct db_sql_connection, 1);
	conn->pool = pool;
	conn->userdb_used = userdb;

	conn->refcount = 1;

	conn->config_path = p_strdup(pool, config_path);
	conn->set = default_db_sql_settings;
	if (!settings_read_nosection(config_path, parse_setting, conn, &error))
		i_fatal("sql %s: %s", config_path, error);

	if (conn->set.password_query == default_db_sql_settings.password_query)
		conn->default_password_query = TRUE;
	if (conn->set.user_query == default_db_sql_settings.user_query)
		conn->default_user_query = TRUE;
	if (conn->set.update_query == default_db_sql_settings.update_query)
		conn->default_update_query = TRUE;
	if (conn->set.iterate_query == default_db_sql_settings.iterate_query)
		conn->default_iterate_query = TRUE;

	if (conn->set.driver == NULL) {
		i_fatal("sql: driver not set in configuration file %s",
			config_path);
	}
	if (conn->set.connect == NULL) {
		i_fatal("sql: connect string not set in configuration file %s",
			config_path);
	}
	i_zero(&set);
	set.driver = conn->set.driver;
	set.connect_string = conn->set.connect;
	if (sql_init_full(&set, &conn->db, &error) < 0) {
		i_fatal("sql: %s", error);
	}

	conn->next = connections;
	connections = conn;
	return conn;
}

void db_sql_unref(struct db_sql_connection **_conn)
{
        struct db_sql_connection *conn = *_conn;

	/* abort all pending auth requests before setting conn to NULL,
	   so that callbacks can still access it */
	sql_disconnect(conn->db);

	*_conn = NULL;
	if (--conn->refcount > 0)
		return;

	sql_unref(&conn->db);
	pool_unref(&conn->pool);
}

void db_sql_connect(struct db_sql_connection *conn)
{
	if (sql_connect(conn->db) < 0 && worker) {
		/* auth worker's sql connection failed. we can't do anything
		   useful until the connection works. there's no point in
		   having tons of worker processes all logging failures,
		   so tell the auth master to stop creating new workers (and
		   maybe close old ones). this handling is especially useful if
		   we reach the max. number of connections for sql server. */
		auth_worker_client_send_error();
	}
}

void db_sql_success(struct db_sql_connection *conn ATTR_UNUSED)
{
	if (worker)
		auth_worker_client_send_success();
}

void db_sql_check_userdb_warning(struct db_sql_connection *conn)
{
	if (worker || conn->userdb_used || conn->set.userdb_warning_disable)
		return;

	if (strcmp(conn->set.user_query,
		   default_db_sql_settings.user_query) != 0) {
		i_warning("sql: Ignoring changed user_query in %s, "
			  "because userdb sql not used. "
			  "(If this is intentional, set userdb_warning_disable=yes)",
			  conn->config_path);
	} else if (strcmp(conn->set.iterate_query,
			  default_db_sql_settings.iterate_query) != 0) {
		i_warning("sql: Ignoring changed iterate_query in %s, "
			  "because userdb sql not used. "
			  "(If this is intentional, set userdb_warning_disable=yes)",
			  conn->config_path);
	}
}

#endif
