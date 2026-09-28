#ifndef SQL_API_PRIVATE_H
#define SQL_API_PRIVATE_H

#include "sql-api.h"
#include "module-context.h"

enum sql_db_state {
	/* not connected to database */
	SQL_DB_STATE_DISCONNECTED,
	/* waiting for connection attempt to succeed or fail */
	SQL_DB_STATE_CONNECTING,
	/* connected, allowing more queries */
	SQL_DB_STATE_IDLE,
	/* connected, no more queries allowed */
	SQL_DB_STATE_BUSY
};

/* <settings checks> */
/* Minimum delay between reconnecting to same server */
#define SQL_CONNECT_MIN_DELAY 1
/* Maximum time to avoiding reconnecting to same server */
#define SQL_CONNECT_MAX_DELAY (60*30)
/* If no servers are connected but a query is requested, try reconnecting to
   next server which has been disconnected longer than this (with a single
   server setup this is really the "max delay" and the SQL_CONNECT_MAX_DELAY
   is never used). */
#define SQL_CONNECT_RESET_DELAY 15
/* Abort connect() if it can't connect within this time. */
#define SQL_CONNECT_TIMEOUT_SECS 5
/* Abort queries after this many seconds */
#define SQL_QUERY_TIMEOUT_SECS 60
/* Default max. number of connections to create per host */
#define SQL_DEFAULT_CONNECTION_LIMIT 5
/* </settings checks> */

#define SQL_DB_IS_READY(db) \
	((db)->state == SQL_DB_STATE_IDLE)
#define SQL_ERRSTR_NOT_CONNECTED "Not connected to database"

/* What is considered slow query */
#define SQL_SLOW_QUERY_MSEC 1000

#define SQL_QUERY_FINISHED "sql_query_finished"
#define SQL_CONNECTION_FINISHED "sql_connection_finished"
#define SQL_TRANSACTION_FINISHED "sql_transaction_finished"

#define SQL_QUERY_FINISHED_FMT "Finished query '%s' in %u msecs"

/* Used by sqlpool to set event_set_ptr(), so sql drivers' init() functions can
   check if the caller is sqlpool. */
#define SQLPOOL_EVENT_PTR "sqlpool_event"

struct sql_db_module_register {
	unsigned int id;
};

union sql_db_module_context {
	struct sql_db_module_register *reg;
};

extern struct sql_db_module_register sql_db_module_register;

extern struct event_category event_category_sql;

struct sql_transaction_query {
	struct sql_transaction_query *next;
	struct sql_transaction_context *trans;

	struct sql_statement *stmt;
	const char *query;
	unsigned int *affected_rows;
};

struct sql_db_vfuncs {
	int (*init)(struct event *event, struct sql_db **db_r,
		    const char **error_r);
	void (*deinit)(struct sql_db *db);
	void (*unref)(struct sql_db *db);
	void (*wait) (struct sql_db *db);

	enum sql_db_flags (*get_flags)(struct sql_db *db);

	int (*connect)(struct sql_db *db);
	void (*disconnect)(struct sql_db *db);
	int (*escape_string)(struct sql_db *db, const char *string,
			     const char **output_r, const char **error_r);

	void (*exec)(struct sql_db *db, const char *query);
	/* Only implement this if the driver can really do asynchronous callbacks,
	   otherwise let sql API handle it. */
	void (*query)(struct sql_db *db, const char *query,
		      sql_query_callback_t *callback, void *context);
	struct sql_result *(*query_s)(struct sql_db *db, const char *query);

	struct sql_transaction_context *(*transaction_begin)(struct sql_db *db);
	/* Only implement this if the driver can really do asynchronous callbacks,
	   otherwise let sql API handle it. */
	void (*transaction_commit)(struct sql_transaction_context *ctx,
				   sql_commit_callback_t *callback,
				   void *context);
	int (*transaction_commit_s)(struct sql_transaction_context *ctx,
				    const char **error_r);
	void (*transaction_rollback)(struct sql_transaction_context *ctx);

	void (*update)(struct sql_transaction_context *ctx, const char *query,
		       unsigned int *affected_rows);
	const char *(*escape_blob)(struct sql_db *db,
				   const unsigned char *data, size_t size);

	struct sql_prepared_statement *
		(*prepared_statement_init)(struct sql_db *db,
					   const char *query_template);
	void (*prepared_statement_deinit)(struct sql_prepared_statement *prep_stmt);


	struct sql_statement *
		(*statement_init)(struct sql_db *db, const char *query_template);
	struct sql_statement *
		(*statement_init_prepared)(struct sql_prepared_statement *prep_stmt);
	void (*statement_abort)(struct sql_statement *stmt);
	void (*statement_set_timestamp)(struct sql_statement *stmt,
					const struct timespec *ts);
	void (*statement_set_no_log_expanded_values)(struct sql_statement *stmt,
						     bool no_expand);
	void (*statement_set_no_log_expanded_value_field)(struct sql_statement *stmt,
							   unsigned int column_idx);
	void (*statement_bind_str)(struct sql_statement *stmt,
				   unsigned int column_idx, const char *value);
	void (*statement_bind_binary)(struct sql_statement *stmt,
				      unsigned int column_idx, const void *value,
				      size_t value_size);
	void (*statement_bind_int64)(struct sql_statement *stmt,
				     unsigned int column_idx, int64_t value);
	void (*statement_bind_double)(struct sql_statement *stmt,
				      unsigned int column_idx, double value);
	void (*statement_bind_uuid)(struct sql_statement *stmt,
				    unsigned int column_idx, const guid_128_t uuid);
	void (*statement_query)(struct sql_statement *stmt,
				sql_query_callback_t *callback, void *context);
	struct sql_result *(*statement_query_s)(struct sql_statement *stmt);
	void (*update_stmt)(struct sql_transaction_context *ctx,
			    struct sql_statement *stmt,
			    unsigned int *affected_rows);

	/* Returns a schema/keyspace followed by a dot '.' OR an empty string
	   if none is required (in order remove the requirement for further
	   checks down the line in format strings et al.) */
	const char *(*table_prefix)(struct sql_db *db);
};

struct sql_db {
	const char *name;
	enum sql_db_flags flags;
	int refcount;

	struct sql_db_vfuncs v;
	ARRAY(union sql_db_module_context *) module_contexts;

	void (*state_change_callback)(struct sql_db *db,
				      enum sql_db_state prev_state,
				      void *context);
	void *state_change_context;

	struct event *event;
	HASH_TABLE(char *, struct sql_prepared_statement *) prepared_stmt_hash;

	struct sql_query_result_delayed *query_delayed_list;
	struct sql_commit_result_delayed *commit_delayed_list;

	enum sql_db_state state;
	/* last time we started connecting to this server
	   (which may or may not have succeeded) */
	time_t last_connect_try;
	unsigned int connect_delay;
	unsigned int connect_failure_count;
	struct timeout *to_reconnect;
	/* last connection error */
	char *last_connect_error;

	uint64_t succeeded_queries;
	uint64_t failed_queries;
	/* includes both succeeded and failed */
	uint64_t slow_queries;

	bool no_reconnect:1;
};

struct sql_result_vfuncs {
	void (*free)(struct sql_result *result);
	int (*next_row)(struct sql_result *result);

	unsigned int (*get_fields_count)(struct sql_result *result);
	const char *(*get_field_name)(struct sql_result *result,
				      unsigned int idx);
	int (*find_field)(struct sql_result *result, const char *field_name);

	const char *(*get_field_value)(struct sql_result *result,
				       unsigned int idx);
	const unsigned char *
		(*get_field_value_binary)(struct sql_result *result,
					  unsigned int idx,
					  size_t *size_r);
	const char *(*find_field_value)(struct sql_result *result,
					const char *field_name);
	const char *const *(*get_values)(struct sql_result *result);

	const char *(*get_error)(struct sql_result *result);
	void (*more)(struct sql_result **result, bool async,
		     sql_query_callback_t *callback, void *context);
};

struct sql_prepared_statement {
	struct sql_db *db;
	int refcount;
	char *query_template;
};

struct sql_statement {
	struct sql_db *db;

	pool_t pool;
	const char *query_template;
	ARRAY_TYPE(const_string) args;
	ARRAY(bool) args_need_escaping;
	/* Byte offsets of the bind placeholders in query_template, in
	   order. Filled once by sql_statement_init_fields(); consumers use
	   these and never scan the template themselves. */
	ARRAY_TYPE(uint) placeholders;
	/* Set by sql_statement_init_fields() when query_template contains a
	   construct sql_template_scan() cannot locate placeholders in
	   reliably. Checked by sql_statement_query(), sql_statement_query_s(),
	   sql_update_stmt() and sql_update_stmt_get_rows() before a driver
	   ever sees the statement, so no driver - whether it binds natively
	   or renders placeholders into the query text from the (possibly
	   only partially filled) offsets array above - can execute a
	   template the scan rejected. */
	const char *template_scan_error;

	/* Tell the driver to not log this query with expanded values.
	   This works only for prepared statements. */
	bool no_log_expanded_values;
	/* Per-field no-log: hide only these bind parameter values when the
	   query is logged, indexed by bind column. Set only for indexes
	   that must stay hidden; unset (or unallocated) indexes log
	   expanded. */
	ARRAY(bool) no_log_fields;
};

struct sql_field_map {
	enum sql_field_type type;
	size_t offset;
};

struct sql_result {
	struct sql_result_vfuncs v;
	int refcount;

	struct sql_db *db;
	const struct sql_field_def *fields;

	unsigned int map_size;
	struct sql_field_map *map;
	void *fetch_dest;
	struct event *event;
	size_t fetch_dest_size;
	enum sql_result_error_type error_type;

	bool failed:1;
	bool failed_try_retry:1;
	bool callback:1;
};

struct sql_transaction_context {
	struct sql_db *db;
	struct event *event;

	/* commit() must use this query list if head is non-NULL. */
	struct sql_transaction_query *head, *tail;

	char *failed_error;
	bool non_atomic;
};

ARRAY_DEFINE_TYPE(sql_drivers, const struct sql_db *);

extern ARRAY_TYPE(sql_drivers) sql_drivers;
extern struct sql_result sql_not_connected_result;

void sql_init_common(struct sql_db *db);

struct sql_db *driver_sqlpool_init(const struct sql_db *driver,
				   struct event *event_parent,
				   const char *filter_name,
				   const ARRAY_TYPE(const_string) *hostnames,
				   unsigned int connection_limit);

void sql_db_set_state(struct sql_db *db, enum sql_db_state state);

inline static const char *sql_db_table_prefix(struct sql_db *db) {
	return db->v.table_prefix == NULL ? "" : db->v.table_prefix(db);
}

void sql_transaction_add_query(struct sql_transaction_context *ctx, pool_t pool,
			       const char *query, unsigned int *affected_rows);
void sql_transaction_add_stmt(struct sql_transaction_context *ctx, pool_t pool,
			      struct sql_statement *stmt, unsigned int *affected_rows);

int sql_statement_get_query(struct sql_statement *stmt,
			    const char **query_r, const char **error_r);

/* Append the byte offset of every bind placeholder found in
   query_template to offsets_r, in order, and return TRUE. A placeholder
   is any '?' outside a single/double-quoted or backtick-quoted string;
   a '?' still inside an unterminated string at the end of the template
   is not counted. This is the only place in lib-sql that decides which
   '?' is a placeholder - everything else consumes the result via
   struct sql_statement.placeholders or sql_template_placeholder_count().

   Returns FALSE with *error_r set, and *offsets_r only partially
   filled, if query_template contains a construct placeholders cannot be
   located in reliably. Each of the following can hide a real
   placeholder while counting an unrelated '?' as one instead, leaving
   the total unchanged from what it would be if nothing were wrong -
   db-sql's placeholder-count check compares only that total against
   the number of %{variable} substitutions, so it cannot catch either
   case; refusing to scan past the construct is the only way to:

     - a backslash inside a '...'-quoted string. Its meaning as a quote
       escape differs by SQL dialect (mysql's backslash escapes the
       following quote; PostgreSQL's standard-conforming string treats
       it as a literal character and closes right at the next quote):
       getting that wrong moves where the string ends, which can both
       count a literal '?' still inside this string and lose a real one
       past it, to a reopened, unterminated string.
     - any unquoted comment introducer ("--", "/ *", "//", "#") or an
       unquoted dollar-quote open tag (PostgreSQL dollar-quoting,
       "$$...$$" or "$tag$...$tag$"). This scanner has no state for a
       comment body or a dollar-quoted string body, so it cannot skip
       over one - only refusing the introducer is safe. The
       dollar-quote case is a concrete instance of the same hazard as
       the backslash above: dollar-quoting exists specifically to
       hold a literal quote character without escaping it (e.g.
       "$$it's ?$$"), and a raw quote inside it opens this scanner's
       own SQUOTE tracking, which then runs past the dollar-quoted
       string's real end looking for a closing quote and swallows
       whatever real placeholder comes next.
       "a = $$x?y's$$ AND b = ?" scans as one placeholder - the phantom
       inside "x?y", not the real one after "b = ", which the runaway
       string ate - the same equal-total mismatch as the backslash case
       (see the test corpus).

   An unquoted '$' followed by a digit, at the same identifier boundary
   as the dollar-quote case above, is rejected for a different reason:
   it is a PostgreSQL positional parameter ($1, $2, ...), not something
   this scanner miscounts. Left unrejected, it would pass through
   unchanged into a query that also uses '?' placeholders, and
   PostgreSQL binds it as an ordinary parameter reference - silently
   reading whatever bind value ends up in that slot instead of erroring
   out.

   A quoted identifier's own dialect-specific syntax is not tracked as
   a state and is not rejected: sqlite's '[ident]' and a PostgreSQL
   array subscript like 'array[?]' use the same '[' ']' characters for
   unrelated things, and the only in-tree use is the array subscript,
   where the '?' really is a placeholder (see the test corpus). A '?'
   inside a literal '[ident]' is therefore just an extra phantom,
   caught the same way as any other overcount below - unless '[ident]'
   itself contains a raw quote character, which would swallow a
   following real placeholder exactly like the dollar-quote case above.
   That residual case is left uncaught: rejecting '[' would also reject
   'array[?]', a real placeholder already relied on.

   Everything that remains after the above only ever changes the total
   placeholder count, never relocates a real placeholder while leaving
   the count the same, so a mismatch is always caught: every backend
   that binds placeholders natively (mysql, PostgreSQL, sqlite)
   validates its own placeholder count independently of this scan.
   Cassandra's non-prepared statement path - the only consumer that
   renders bind values into the query text using these offsets directly
   - has no comment or dollar-quoting syntax left to trigger a mismatch,
   since both are rejected above. CQL does have bracket syntax
   (m['key'] collection element access), but a well-formed CQL bracket
   expression closes an embedded quote by doubling it, the same
   convention this scanner's SQUOTE state already handles, so it cannot
   leave the unbalanced quote the '[ident]' hazard above depends on. */
bool sql_template_scan(const char *query_template,
		       ARRAY_TYPE(uint) *offsets_r, const char **error_r);

void sql_connection_log_finished(struct sql_db *db);
struct event_passthrough *
sql_query_finished_event(struct sql_db *db, struct event *event, const char *query,
			 bool success, int *duration_r);
struct event_passthrough *sql_transaction_finished_event(struct sql_transaction_context *ctx);

/* default functions */
void default_sql_prepared_statement_deinit(struct sql_prepared_statement *prep_stmt);
struct sql_prepared_statement *
default_sql_prepared_statement_init(struct sql_db *db,
				    const char *query_template);

void default_sql_statement_query(struct sql_statement *stmt,
			    sql_query_callback_t *callback, void *context);
struct sql_result *
default_sql_statement_query_s(struct sql_statement *stmt);
void default_sql_update_stmt(struct sql_transaction_context *ctx,
				    struct sql_statement *stmt,
				    unsigned int *affected_rows);

void sql_drivers_init_without_drivers(void);
void sql_drivers_deinit_without_drivers(void);

void sql_drivers_init_all(void);
void sql_drivers_deinit_all(void);

void driver_cassandra_init(void);
void driver_cassandra_deinit(void);
void driver_mysql_init(void);
void driver_mysql_deinit(void);
void driver_pgsql_init(void);
void driver_pgsql_deinit(void);
void driver_sqlite_init(void);
void driver_sqlite_deinit(void);

#endif
