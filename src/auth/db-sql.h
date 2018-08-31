#ifndef DB_SQL_H
#define DB_SQL_H

#include "sql-api.h"

struct db_sql_settings {
	const char *driver;
	const char *connect;
	const char *password_query;
	const char *user_query;
	const char *update_query;
	const char *iterate_query;
	const char *default_pass_scheme;
	bool userdb_warning_disable;
};

struct db_sql_connection {
	struct db_sql_connection *next;

	pool_t pool;
	int refcount;

	char *config_path;
	struct db_sql_settings set;
	struct sql_db *db;

	bool default_password_query:1;
	bool default_user_query:1;
	bool default_update_query:1;
	bool default_iterate_query:1;
	bool userdb_used:1;
};

struct db_sql_connection *db_sql_init(const char *config_path, bool userdb);
void db_sql_unref(struct db_sql_connection **conn);

void db_sql_connect(struct db_sql_connection *conn);
void db_sql_success(struct db_sql_connection *conn);

void db_sql_check_userdb_warning(struct db_sql_connection *conn);

#endif
