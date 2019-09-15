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

#define SQL_DB_IS_READY(db) \
	((db)->state == SQL_DB_STATE_IDLE)
#define SQL_ERRSTR_NOT_CONNECTED "Not connected to database"

/* What is considered slow query */
#define SQL_SLOW_QUERY_MSEC 1000

#define SQL_QUERY_FINISHED "sql_query_finished"
#define SQL_CONNECTION_FINISHED "sql_connection_finished"
#define SQL_TRANSACTION_FINISHED "sql_transaction_finished"

#define SQL_QUERY_FINISHED_FMT "Finished query '%s' in %u msecs"

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

	const char *query;
	unsigned int *affected_rows;
};

struct sql_db_vfuncs {
	struct sql_db *(*init)(const char *connect_string);
	int (*init_full)(const struct sql_settings *set, struct sql_db **db_r,
			 const char **error);
	void (*deinit)(struct sql_db *db);

	int (*connect)(struct sql_db *db);
	void (*disconnect)(struct sql_db *db);
	const char *(*escape_string)(struct sql_db *db, const char *string);

	void (*exec)(struct sql_db *db, const char *query);
	void (*query)(struct sql_db *db, const char *query,
		      sql_query_callback_t *callback, void *context);
	struct sql_result *(*query_s)(struct sql_db *db, const char *query);

	struct sql_transaction_context *(*transaction_begin)(struct sql_db *db);
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
	void (*statement_bind_str)(struct sql_statement *stmt,
				   unsigned int column_idx, const char *value);
	void (*statement_bind_binary)(struct sql_statement *stmt,
				      unsigned int column_idx, const void *value,
				      size_t value_size);
	void (*statement_bind_int64)(struct sql_statement *stmt,
				     unsigned int column_idx, int64_t value);
	void (*statement_query)(struct sql_statement *stmt,
				sql_query_callback_t *callback, void *context);
	struct sql_result *(*statement_query_s)(struct sql_statement *stmt);
	void (*update_stmt)(struct sql_transaction_context *ctx,
			    struct sql_statement *stmt,
			    unsigned int *affected_rows);
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

	enum sql_db_state state;
	/* last time we started connecting to this server
	   (which may or may not have succeeded) */
	time_t last_connect_try;
	unsigned int connect_delay;
	unsigned int connect_failure_count;
	struct timeout *to_reconnect;

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
	char *query_template;
};

struct sql_statement {
	struct sql_db *db;

	pool_t pool;
	const char *query_template;
	ARRAY_TYPE(const_string) args;
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
};

ARRAY_DEFINE_TYPE(sql_drivers, const struct sql_db *);

extern ARRAY_TYPE(sql_drivers) sql_drivers;
extern struct sql_result sql_not_connected_result;

struct sql_db *
driver_sqlpool_init(const char *connect_string, const struct sql_db *driver);
int driver_sqlpool_init_full(const struct sql_settings *set, const struct sql_db *driver,
			     struct sql_db **db_r, const char **error_r);

void sql_db_set_state(struct sql_db *db, enum sql_db_state state);

void sql_transaction_add_query(struct sql_transaction_context *ctx, pool_t pool,
			       const char *query, unsigned int *affected_rows);
const char *sql_statement_get_query(struct sql_statement *stmt);

void sql_connection_log_finished(struct sql_db *db);
struct event_passthrough *
sql_query_finished_event(struct sql_db *db, struct event *event, const char *query,
			 bool success, int *duration_r);
struct event_passthrough *sql_transaction_finished_event(struct sql_transaction_context *ctx);
#endif
