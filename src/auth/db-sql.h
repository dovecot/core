#ifndef DB_SQL_H
#define DB_SQL_H

#include "sql-api.h"

struct sql_settings {
	const char *driver;
	const char *connect;
	const char *password_query;
	const char *user_query;
	const char *update_query;
	const char *iterate_query;
	const char *default_pass_scheme;
	bool userdb_warning_disable;
};

struct sql_connection {
	struct sql_connection *next;

	pool_t pool;
	int refcount;

	char *config_path;
	struct sql_settings set;
	struct sql_db *db;

	unsigned int default_password_query:1;
	unsigned int default_user_query:1;
	unsigned int default_update_query:1;
	unsigned int default_iterate_query:1;
	unsigned int userdb_used:1;
};

struct sql_connection *db_sql_init(const char *config_path, bool userdb);
void db_sql_unref(struct sql_connection **conn);

void db_sql_connect(struct sql_connection *conn);
void db_sql_success(struct sql_connection *conn);

void db_sql_check_userdb_warning(struct sql_connection *conn);

#endif
