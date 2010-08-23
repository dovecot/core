#ifndef SQL_API_H
#define SQL_API_H

/* This SQL API is designed to work asynchronously. The underlying drivers
   however may not. */

enum sql_db_flags {
	/* Set if queries are not executed asynchronously */
	SQL_DB_FLAG_BLOCKING		= 0x01,
	/* Set if database wants to use connection pooling */
	SQL_DB_FLAG_POOLED		= 0x02
};

enum sql_field_type {
	SQL_TYPE_STR,
	SQL_TYPE_UINT,
	SQL_TYPE_ULLONG,
	SQL_TYPE_BOOL
};

struct sql_field_def {
	enum sql_field_type type;
	const char *name;
	size_t offset;
};

#define SQL_DEF_STRUCT(name, struct_name, type, c_type) \
	{ (type) + COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		((struct struct_name *)0)->name, c_type), \
	  #name, offsetof(struct struct_name, name) }

#define SQL_DEF_STRUCT_STR(name, struct_name) \
	SQL_DEF_STRUCT(name, struct_name, SQL_TYPE_STR, const char *)
#define SQL_DEF_STRUCT_UINT(name, struct_name) \
	SQL_DEF_STRUCT(name, struct_name, SQL_TYPE_UINT, unsigned int)
#define SQL_DEF_STRUCT_ULLONG(name, struct_name) \
	SQL_DEF_STRUCT(name, struct_name, SQL_TYPE_ULLONG, unsigned long long)
#define SQL_DEF_STRUCT_BOOL(name, struct_name) \
	SQL_DEF_STRUCT(name, struct_name, SQL_TYPE_BOOL, bool)

struct sql_db;
struct sql_result;

typedef void sql_query_callback_t(struct sql_result *result, void *context);
typedef void sql_commit_callback_t(const char *error, void *context);

void sql_drivers_init(void);
void sql_drivers_deinit(void);

/* register all built-in SQL drivers */
void sql_drivers_register_all(void);

void sql_driver_register(const struct sql_db *driver);
void sql_driver_unregister(const struct sql_db *driver);

/* Initialize database connections. db_driver is the database driver name,
   eg. "mysql" or "pgsql". connect_string is driver-specific. */
struct sql_db *sql_init(const char *db_driver, const char *connect_string);
void sql_deinit(struct sql_db **db);

/* Returns SQL database state flags. */
enum sql_db_flags sql_get_flags(struct sql_db *db);

/* Explicitly connect to the database. It's not required to call this function
   though. Returns -1 if we're not connected, 0 if we started connecting or
   1 if we are fully connected now. */
int sql_connect(struct sql_db *db);
/* Explicitly disconnect from database and abort pending auth requests. */
void sql_disconnect(struct sql_db *db);

/* Escape the given string if needed and return it. */
const char *sql_escape_string(struct sql_db *db, const char *string);

/* Execute SQL query without waiting for results. */
void sql_exec(struct sql_db *db, const char *query);
/* Execute SQL query and return result in callback. If fields list is given,
   the returned fields are validated to be of correct type, and you can use
   sql_result_next_row_get() */
void sql_query(struct sql_db *db, const char *query,
	       sql_query_callback_t *callback, void *context);
#ifdef CONTEXT_TYPE_SAFETY
#  define sql_query(db, query, callback, context) \
	({(void)(1 ? 0 : callback((struct sql_result *)NULL, context)); \
	  sql_query(db, query, \
		(sql_query_callback_t *)callback, context); })
#else
#  define sql_query(db, query, callback, context) \
	sql_query(db, query, (sql_query_callback_t *)callback, context)
#endif
/* Execute blocking SQL query and return result. */
struct sql_result *sql_query_s(struct sql_db *db, const char *query);

void sql_result_setup_fetch(struct sql_result *result,
			    const struct sql_field_def *fields,
			    void *dest, size_t dest_size);

/* Go to next row, returns 1 if ok, 0 if this was the last row or -1 if error
   occurred. This needs to be the first call for result. */
int sql_result_next_row(struct sql_result *result);

void sql_result_ref(struct sql_result *result);
/* Needs to be called only with sql_query_s() or when result has been
   explicitly referenced. */
void sql_result_unref(struct sql_result *result);

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
const unsigned char *
sql_result_get_field_value_binary(struct sql_result *result,
				  unsigned int idx, size_t *size_r);
const char *sql_result_find_field_value(struct sql_result *result,
					const char *field_name);
/* Return all values of current row. */
const char *const *sql_result_get_values(struct sql_result *result);

/* Return last error message in result. */
const char *sql_result_get_error(struct sql_result *result);

/* Begin a new transaction. Currently you're limited to only one open
   transaction at a time. */
struct sql_transaction_context *sql_transaction_begin(struct sql_db *db);
/* Commit transaction. */
void sql_transaction_commit(struct sql_transaction_context **ctx,
			    sql_commit_callback_t *callback, void *context);
#ifdef CONTEXT_TYPE_SAFETY
#  define sql_transaction_commit(ctx, callback, context) \
	({(void)(1 ? 0 : callback((const char *)NULL, context)); \
	  sql_transaction_commit(ctx, \
		(sql_commit_callback_t *)callback, context); })
#else
#  define sql_transaction_commit(ctx, callback, context) \
	  sql_transaction_commit(ctx, \
		(sql_commit_callback_t *)callback, context)
#endif
/* Synchronous commit. Returns 0 if ok, -1 if error. */
int sql_transaction_commit_s(struct sql_transaction_context **ctx,
			     const char **error_r);
void sql_transaction_rollback(struct sql_transaction_context **ctx);

/* Execute query in given transaction. */
void sql_update(struct sql_transaction_context *ctx, const char *query);
/* Save the number of rows updated by this query. The value is set before
   commit callback is called. */
void sql_update_get_rows(struct sql_transaction_context *ctx, const char *query,
			 unsigned int *affected_rows);

#endif
