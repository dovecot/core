#ifndef __SQL_API_H
#define __SQL_API_H

enum sql_db_flags {
	/* Set if queries are not executed asynchronously */
	SQL_DB_FLAG_BLOCKING		= 0x01,
};

/* This SQL API is designed to work asynchronously. The underlying drivers
   however may not. */

struct sql_db;
struct sql_result;

typedef void sql_query_callback_t(struct sql_result *result, void *context);

/* Initialize database connections. db_driver is the database driver name,
   eg. "mysql" or "pgsql". connect_string is driver-specific. */
struct sql_db *sql_init(const char *db_driver, const char *connect_string);
void sql_deinit(struct sql_db *db);

/* Returns SQL database state flags. */
enum sql_db_flags sql_get_flags(struct sql_db *db);

/* Explicitly connect to the database. It's not required to call this function
   though. Returns -1 if we're not connected, 0 if we started connecting or
   1 if we are fully connected now. */
int sql_connect(struct sql_db *db);

/* Execute SQL query without waiting for results. */
void sql_exec(struct sql_db *db, const char *query);
/* Execute SQL query and return result in callback. */
void sql_query(struct sql_db *db, const char *query,
	       sql_query_callback_t *callback, void *context);

/* Go to next row, returns 1 if ok, 0 if this was the last row or -1 if error
   occured. This needs to be the first call for result. */
int sql_result_next_row(struct sql_result *result);

/* Return number of fields in result. */
unsigned int sql_result_get_fields_count(struct sql_result *result);
/* Return name of the given field index. */
const char *sql_result_get_field_name(struct sql_result *result,
				      unsigned int idx);
/* Return field index for given name, or -1 if not found. */
int sql_result_find_field(struct sql_result *result, const char *field_name);

/* Returns value of given field as string. */
const char *sql_result_get_field_value(struct sql_result *result,
				       unsigned int idx);
const char *sql_result_find_field_value(struct sql_result *result,
					const char *field_name);
/* Return all values of current row. */
const char *const *sql_result_get_values(struct sql_result *result);

/* Return last error message in result. */
const char *sql_result_get_error(struct sql_result *result);

#endif
