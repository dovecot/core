#ifndef SQL_API_H
#define SQL_API_H

struct timespec;

/* This SQL API is designed to work asynchronously. The underlying drivers
   however may not. */

enum sql_db_flags {
	/* Set if queries are not executed asynchronously */
	SQL_DB_FLAG_BLOCKING		= 0x01,
	/* Set if database wants to use connection pooling */
	SQL_DB_FLAG_POOLED		= 0x02,
	/* Prepared statements are supported by the database. If they aren't,
	   the functions can still be used, but they're just internally
	   convered into regular statements. */
	SQL_DB_FLAG_PREP_STATEMENTS	= 0x04,
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

enum sql_result_error_type {
	SQL_RESULT_ERROR_TYPE_UNKNOWN = 0,
	/* It's unknown whether write succeeded or not. This could be due to
	   a timeout or a disconnection from server. */
	SQL_RESULT_ERROR_TYPE_WRITE_UNCERTAIN
};

enum sql_result_next {
	/* Row was returned */
	SQL_RESULT_NEXT_OK = 1,
	/* There are no more rows */
	SQL_RESULT_NEXT_LAST = 0,
	/* Error occurred - see sql_result_get_error*() */
	SQL_RESULT_NEXT_ERROR = -1,
	/* There are more results - call sql_result_more() */
	SQL_RESULT_NEXT_MORE = -99
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

struct sql_commit_result {
	const char *error;
	enum sql_result_error_type error_type;
};

struct sql_settings {
	const char *driver;
	const char *connect_string;
	struct event *event_parent;
};

typedef void sql_query_callback_t(struct sql_result *result, void *context);
typedef void sql_commit_callback_t(const struct sql_commit_result *result, void *context);

void sql_drivers_init(void);
void sql_drivers_deinit(void);

/* register all built-in SQL drivers */
void sql_drivers_register_all(void);

void sql_driver_register(const struct sql_db *driver);
void sql_driver_unregister(const struct sql_db *driver);

/* Initialize database connections. db_driver is the database driver name,
   eg. "mysql" or "pgsql". connect_string is driver-specific. */
struct sql_db *sql_init(const char *db_driver, const char *connect_string);
int sql_init_full(const struct sql_settings *set, struct sql_db **db_r,
		  const char **error_r);

void sql_ref(struct sql_db *db);
void sql_unref(struct sql_db **db);

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
/* Escape the given data as a string. */
const char *sql_escape_blob(struct sql_db *db,
			    const unsigned char *data, size_t size);

/* Execute SQL query without waiting for results. */
void sql_exec(struct sql_db *db, const char *query);
/* Execute SQL query and return result in callback. If fields list is given,
   the returned fields are validated to be of correct type, and you can use
   sql_result_next_row_get() */
void sql_query(struct sql_db *db, const char *query,
	       sql_query_callback_t *callback, void *context);
#define sql_query(db, query, callback, context) \
	sql_query(db, query - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct sql_result *, typeof(context))), \
		(sql_query_callback_t *)callback, context)
/* Execute blocking SQL query and return result. */
struct sql_result *sql_query_s(struct sql_db *db, const char *query);

struct sql_prepared_statement *
sql_prepared_statement_init(struct sql_db *db, const char *query_template);
void sql_prepared_statement_unref(struct sql_prepared_statement **prep_stmt);

struct sql_statement *
sql_statement_init(struct sql_db *db, const char *query_template);
struct sql_statement *
sql_statement_init_prepared(struct sql_prepared_statement *prep_stmt);
void sql_statement_abort(struct sql_statement **stmt);
void sql_statement_set_timestamp(struct sql_statement *stmt,
				 const struct timespec *ts);
void sql_statement_bind_str(struct sql_statement *stmt,
			    unsigned int column_idx, const char *value);
void sql_statement_bind_binary(struct sql_statement *stmt,
			       unsigned int column_idx, const void *value,
			       size_t value_size);
void sql_statement_bind_int64(struct sql_statement *stmt,
			      unsigned int column_idx, int64_t value);
void sql_statement_query(struct sql_statement **stmt,
			 sql_query_callback_t *callback, void *context);
#define sql_statement_query(stmt, callback, context) \
	sql_statement_query(stmt, \
		(sql_query_callback_t *)callback, context - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct sql_result *, typeof(context))))
struct sql_result *sql_statement_query_s(struct sql_statement **stmt);

void sql_result_setup_fetch(struct sql_result *result,
			    const struct sql_field_def *fields,
			    void *dest, size_t dest_size);

/* Go to next row. See enum sql_result_next. */
int sql_result_next_row(struct sql_result *result);

/* If sql_result_next_row() returned SQL_RESULT_NEXT_MORE, this can be called
   to continue returning more results. The result is freed with this call, so
   it must not be accesed anymore until the callback is finished. */
void sql_result_more(struct sql_result **result,
		     sql_query_callback_t *callback, void *context);
#define sql_result_more(result, callback, context) \
	sql_result_more(result - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct sql_result *, typeof(context))), \
		(sql_query_callback_t *)callback, context)
/* Synchronous version of sql_result_more(). The result will be replaced with
   the new result. */
void sql_result_more_s(struct sql_result **result);

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

/* Returns value of given field as string. Note that it can be NULL. */
const char *sql_result_get_field_value(struct sql_result *result,
				       unsigned int idx);
/* Returns a binary value. Note that a NULL is returned as NULL with size=0,
   while empty string returns non-NULL with size=0. */
const unsigned char *
sql_result_get_field_value_binary(struct sql_result *result,
				  unsigned int idx, size_t *size_r);
/* Find the field and return its value. NULL return value can mean that either
   the field didn't exist or that its value is NULL. */
const char *sql_result_find_field_value(struct sql_result *result,
					const char *field_name);
/* Return all values of current row. Note that this array is not
   NULL-terminated - you must use sql_result_get_fields_count() to find out
   the array's length. It's also possible that some of the values inside the
   array are NULL. */
const char *const *sql_result_get_values(struct sql_result *result);

/* Return last error message in result. */
const char *sql_result_get_error(struct sql_result *result);
enum sql_result_error_type sql_result_get_error_type(struct sql_result *result);

/* Begin a new transaction. Currently you're limited to only one open
   transaction at a time. */
struct sql_transaction_context *sql_transaction_begin(struct sql_db *db);
/* Commit transaction. */
void sql_transaction_commit(struct sql_transaction_context **ctx,
			    sql_commit_callback_t *callback, void *context);
#define sql_transaction_commit(ctx, callback, context) \
	  sql_transaction_commit(ctx - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct sql_commit_result *, typeof(context))), \
		(sql_commit_callback_t *)callback, context)
/* Synchronous commit. Returns 0 if ok, -1 if error. */
int sql_transaction_commit_s(struct sql_transaction_context **ctx,
			     const char **error_r);
void sql_transaction_rollback(struct sql_transaction_context **ctx);

/* Execute query in given transaction. */
void sql_update(struct sql_transaction_context *ctx, const char *query);
void sql_update_stmt(struct sql_transaction_context *ctx,
		     struct sql_statement **stmt);
/* Save the number of rows updated by this query. The value is set before
   commit callback is called. */
void sql_update_get_rows(struct sql_transaction_context *ctx, const char *query,
			 unsigned int *affected_rows);
void sql_update_stmt_get_rows(struct sql_transaction_context *ctx,
			      struct sql_statement **stmt,
			      unsigned int *affected_rows);

#endif
