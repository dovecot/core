#ifndef __SQL_API_PRIVATE_H
#define __SQL_API_PRIVATE_H

#include "sql-api.h"

struct sql_db {
	struct sql_db *(*init)(const char *connect_string);
	void (*deinit)(struct sql_db *db);

	void (*exec)(struct sql_db *db, const char *query);
	void (*query)(struct sql_db *db, const char *query,
		      sql_query_callback_t *callback, void *context);
};

struct sql_result {
	struct sql_db *db;

	int (*next_row)(struct sql_result *result);

	unsigned int (*get_fields_count)(struct sql_result *result);
	const char *(*get_field_name)(struct sql_result *result,
				      unsigned int idx);
	int (*find_field)(struct sql_result *result, const char *field_name);

	const char *(*get_field_value)(struct sql_result *result,
				       unsigned int idx);
	const char *(*find_field_value)(struct sql_result *result,
					const char *field_name);
	const char *const *(*get_values)(struct sql_result *result);

	const char *(*get_error)(struct sql_result *result);
};

extern struct sql_db driver_mysql_db;
extern struct sql_db driver_pgsql_db;

extern struct sql_result sql_not_connected_result;

#endif
