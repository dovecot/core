#ifndef DB_SQL_H
#define DB_SQL_H

#include "sql-api.h"

void db_sql_connect(struct sql_db *db);
void db_sql_success(void);

int db_sql_create_statement(struct sql_db *db, const char *query,
			    struct auth_request *request,
			    struct sql_statement **stmt_r, const char **error_r);

#endif
