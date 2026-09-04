/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "test-common.h"
#include "sql-api-private.h"
#include "driver-test.h"

/* A sqlpool wrapped around a single driver-test connection, with the
   connection pinned to SQL_DB_STATE_BUSY (not ready) from the start.

   The state is set directly with sql_db_set_state() rather than reached
   through sql_connect()/sql_disconnect(), which would fold in the generic
   SQL_CONNECT_MIN_DELAY throttle and make "not ready yet" depend on
   wall-clock timing - the flakiness the live-mysql version of these tests
   had. Setting the state directly is exactly what a real driver's
   connect/query completion does before calling sql_db_set_state() itself,
   so this still exercises the real sqlpool_state_changed() ->
   sqlpool_request_send_next() path the fixes are in. */
struct test_sqlpool {
	struct sql_db *pool;
	struct sql_db *conndb;
};

/* driver_sqlpool_init() creates its connections by calling driver->v.init()
   itself, so the only way to learn the resulting per-connection sql_db is
   to intercept that call. */
static struct sql_db *test_sqlpool_conn_db;

static int
test_sqlpool_conn_init(struct event *event, struct sql_db **db_r,
		       const char **error_r)
{
	int ret = driver_test_mysql_db.v.init(event, db_r, error_r);
	if (ret == 0)
		test_sqlpool_conn_db = *db_r;
	return ret;
}

static void test_sqlpool_init(struct test_sqlpool *ts, const char *filter_name)
{
	static struct sql_db driver;
	driver = driver_test_mysql_db;
	driver.v.init = test_sqlpool_conn_init;

	ARRAY_TYPE(const_string) hosts;
	i_array_init(&hosts, 1);
	const char *host = "test";
	array_push_back(&hosts, &host);

	struct event *event = event_create(NULL);
	test_sqlpool_conn_db = NULL;
	ts->pool = driver_sqlpool_init(&driver, event, filter_name, &hosts, 1);
	event_unref(&event);
	array_free(&hosts);

	i_assert(test_sqlpool_conn_db != NULL);
	ts->conndb = test_sqlpool_conn_db;
	ts->conndb->state = SQL_DB_STATE_BUSY;
}

struct test_sqlpool_commit_ctx {
	bool got_first;
	bool got_second;
};

static void
test_sqlpool_commit_first_callback(const struct sql_commit_result *result,
				   struct test_sqlpool_commit_ctx *ctx)
{
	test_assert(result->error == NULL);
	ctx->got_first = TRUE;
}

static void
test_sqlpool_commit_second_callback(const struct sql_commit_result *result,
				    struct test_sqlpool_commit_ctx *ctx)
{
	test_assert(result->error == NULL);
	ctx->got_second = TRUE;
}

/* A transaction commit queued because the sqlpool's only connection wasn't
   ready must not be the only request that a later connection-ready state
   change resumes: whatever is queued behind it must run too, rather than
   sit until the request timeout. This is the driver_sqlpool_commit_callback()
   drain. */
static void test_sql_sqlpool_commit_queue_drain(void)
{
	test_begin("sqlpool commit queue drain");

	struct ioloop *ioloop = io_loop_create();
	struct test_sqlpool ts;
	test_sqlpool_init(&ts, "test_sqlpool_commit_queue_drain");

	struct test_sqlpool_commit_ctx ctx = { FALSE, FALSE };

	/* both transactions must queue instead of committing right away */
	struct sql_transaction_context *t1 = sql_transaction_begin(ts.pool);
	sql_transaction_commit(&t1, test_sqlpool_commit_first_callback, &ctx);
	struct sql_transaction_context *t2 = sql_transaction_begin(ts.pool);
	sql_transaction_commit(&t2, test_sqlpool_commit_second_callback, &ctx);
	test_assert(!ctx.got_first && !ctx.got_second);

	/* connection becomes idle: must drain the whole queue, not just
	   the request this state change directly dispatches */
	sql_db_set_state(ts.conndb, SQL_DB_STATE_IDLE);

	test_assert(ctx.got_first);
	test_assert(ctx.got_second);

	sql_unref(&ts.pool);
	io_loop_destroy(&ioloop);

	test_end();
}

/* driver_sqlpool_transaction_commit_s() (the synchronous commit path) has
   the same missing-drain gap the two async completion paths above were
   fixed for: once it's done with the connection, whatever else is queued
   behind it must still get to run.

   The sync path never goes through sql_db_set_state(), so unlike the
   test above, the connection here is made ready with a direct field
   write instead of sql_db_set_state(): that's what leaves it ready
   without sqlpool_state_changed() ever running to drain the queue
   itself, which is exactly the condition this drain call exists for. */
static void test_sql_sqlpool_commit_s_queue_drain(void)
{
	test_begin("sqlpool sync commit queue drain");

	struct ioloop *ioloop = io_loop_create();
	struct test_sqlpool ts;
	test_sqlpool_init(&ts, "test_sqlpool_commit_s_queue_drain");

	struct test_sqlpool_commit_ctx ctx = { FALSE, FALSE };

	/* queues: no ready connection yet */
	struct sql_transaction_context *t1 = sql_transaction_begin(ts.pool);
	sql_transaction_commit(&t1, test_sqlpool_commit_first_callback, &ctx);
	test_assert(!ctx.got_first);

	ts.conndb->state = SQL_DB_STATE_IDLE;
	test_assert(!ctx.got_first);

	struct sql_transaction_context *t2 = sql_transaction_begin(ts.pool);
	const char *error = NULL;
	test_assert(sql_transaction_commit_s(&t2, &error) == 0);
	test_assert(error == NULL);

	/* the sync commit's own drain call must have resumed t1 */
	test_assert(ctx.got_first);

	sql_unref(&ts.pool);
	io_loop_destroy(&ioloop);

	test_end();
}

struct test_sqlpool_abort_ctx {
	bool got_callback;
	const char *error;
};

static void
test_sqlpool_abort_callback(const struct sql_commit_result *result,
			    struct test_sqlpool_abort_ctx *ctx)
{
	ctx->got_callback = TRUE;
	ctx->error = result->error;
}

/* sqlpool_request_abort() must resolve a still-queued transaction commit
   it never got to send, not just drop it: the caller is otherwise left
   waiting for a callback that never arrives, and the transaction context
   itself leaks. Deinit while a commit is still queued is what runs this
   path - driver_sqlpool_abort_requests() walks the queue and aborts every
   request left in it. */
static void test_sql_sqlpool_abort_queued_commit(void)
{
	test_begin("sqlpool abort queued commit");

	struct ioloop *ioloop = io_loop_create();
	struct test_sqlpool ts;
	test_sqlpool_init(&ts, "test_sqlpool_abort_queued_commit");

	struct test_sqlpool_abort_ctx ctx = { FALSE, NULL };

	/* queues: no ready connection yet, and never becomes one */
	struct sql_transaction_context *t = sql_transaction_begin(ts.pool);
	sql_transaction_commit(&t, test_sqlpool_abort_callback, &ctx);
	test_assert(!ctx.got_callback);

	sql_unref(&ts.pool);

	test_assert(ctx.got_callback);
	test_assert(ctx.error != NULL);

	io_loop_destroy(&ioloop);

	test_end();
}

struct test_sqlpool_stmt_ctx {
	bool got_a;
	bool got_b;
};

static void
test_sqlpool_stmt_a_callback(struct sql_result *result,
			     struct test_sqlpool_stmt_ctx *ctx)
{
	test_assert(sql_result_next_row(result) == SQL_RESULT_NEXT_LAST);
	ctx->got_a = TRUE;
	sql_result_unref(result);
}

static void
test_sqlpool_stmt_b_callback(struct sql_result *result,
			     struct test_sqlpool_stmt_ctx *ctx)
{
	test_assert(sql_result_next_row(result) == SQL_RESULT_NEXT_LAST);
	ctx->got_b = TRUE;
	sql_result_unref(result);
}

/* Same as above, for a statement queued via driver_sqlpool_statement_query():
   this is the driver_sqlpool_statement_query_callback() drain. */
static void test_sql_sqlpool_statement_queue_drain(void)
{
	test_begin("sqlpool statement queue drain");

	struct ioloop *ioloop = io_loop_create();
	struct test_sqlpool ts;
	test_sqlpool_init(&ts, "test_sqlpool_statement_queue_drain");

	/* statements with no placeholders render to plain text unchanged,
	   so these are also what driver-test must see as the query */
	struct test_driver_result result_a = {
		.nqueries = 1,
		.queries = (const char *[]){"INSERT INTO bar VALUES('queued_a')"},
	};
	struct test_driver_result result_b = {
		.nqueries = 1,
		.queries = (const char *[]){"INSERT INTO bar VALUES('queued_b')"},
	};
	sql_driver_test_add_expected_result(ts.conndb, &result_a);
	sql_driver_test_add_expected_result(ts.conndb, &result_b);

	struct test_sqlpool_stmt_ctx ctx = { FALSE, FALSE };

	struct sql_statement *stmt_a =
		sql_statement_init(ts.pool, "INSERT INTO bar VALUES('queued_a')");
	sql_statement_query(&stmt_a, test_sqlpool_stmt_a_callback, &ctx);
	struct sql_statement *stmt_b =
		sql_statement_init(ts.pool, "INSERT INTO bar VALUES('queued_b')");
	sql_statement_query(&stmt_b, test_sqlpool_stmt_b_callback, &ctx);
	test_assert(!ctx.got_a && !ctx.got_b);

	sql_db_set_state(ts.conndb, SQL_DB_STATE_IDLE);

	test_assert(ctx.got_a);
	test_assert(ctx.got_b);

	sql_unref(&ts.pool);
	io_loop_destroy(&ioloop);

	test_end();
}

/* driver_sqlpool_update_stmt() must not fall back to rendering the
   statement to plain text when no connection was available at
   statement_init() time (pool_stmt->stmt == NULL): that renders every
   bound value into the query text via sql_statement_get_query(), which
   ignores no_log_expanded_values, defeating hide_log_values on this path.
   It must defer instead, keeping the transaction entry as the statement
   itself until a connection is known. */
static void test_sql_sqlpool_update_stmt_no_connection(void)
{
	test_begin("sqlpool update_stmt defers without a connection");

	struct ioloop *ioloop = io_loop_create();
	struct test_sqlpool ts;
	test_sqlpool_init(&ts, "test_sqlpool_update_stmt_no_connection");

	/* the sole connection is BUSY (see test_sqlpool_init()'s comment),
	   so statement_init() finds no connection and pool_stmt->stmt stays
	   NULL. */
	struct sql_statement *stmt = sql_statement_init(
		ts.pool, "UPDATE users SET pass = ? WHERE user = ?");
	sql_statement_bind_str(stmt, 0, "hunter2");
	sql_statement_bind_str(stmt, 1, "user");
	sql_statement_set_no_log_expanded_values(stmt, TRUE);

	struct sql_transaction_context *trans = sql_transaction_begin(ts.pool);
	sql_update_stmt(trans, &stmt);

	test_assert(trans->head != NULL && trans->head == trans->tail);
	if (trans->head != NULL) {
		test_assert(trans->head->stmt != NULL);
		test_assert(trans->head->query == NULL);
		if (trans->head->query != NULL)
			test_assert(strstr(trans->head->query, "hunter2") == NULL);
		if (trans->head->stmt != NULL) {
			const char *log_query =
				sql_statement_get_log_query(trans->head->stmt);
			test_assert(strstr(log_query, "hunter2") == NULL);
		}
	}

	/* connection becomes ready: the commit must resolve the deferred
	   statement and replay its binds without crashing. */
	ts.conndb->state = SQL_DB_STATE_IDLE;
	const char *error = NULL;
	test_assert(sql_transaction_commit_s(&trans, &error) == 0);
	test_assert(error == NULL);

	sql_unref(&ts.pool);
	io_loop_destroy(&ioloop);

	test_end();
}

static void
test_sql_sqlpool_statement_scan_error_callback(struct sql_result *result,
					       bool *got_result_r)
{
	test_assert(sql_result_next_row(result) == SQL_RESULT_NEXT_ERROR);
	test_assert_strcmp(sql_result_get_error(result),
		"query template has a '#' comment outside a quoted string - "
		"comments are not allowed in a query template; bind "
		"placeholders after it cannot be located reliably");
	*got_result_r = TRUE;
	/* sql_query_delayed_callback() (this result was built by
	   sql_query_callback_delayed()) unrefs the result itself right
	   after this callback returns - unlike a result delivered through
	   a real async driver's own .query(), which hands ownership to the
	   callback. Unref'ing it here too double-frees it. */
	io_loop_stop(current_ioloop);
}

/* An unscannable template must fail through the async sql_statement_query()
   entry point too, before the statement ever reaches a driver - including
   a pooled one. The connection is IDLE before sql_statement_init() runs,
   so driver_sqlpool_statement_init() creates its nested per-connection
   statement immediately rather than deferring it; only
   sql_statement_abort(), not a raw pool_unref(), frees that nested
   statement, so this is also the case a leak would show up in under
   valgrind. */
static void test_sql_sqlpool_statement_scan_error(void)
{
	test_begin("sqlpool statement scan error frees nested statement");

	struct ioloop *ioloop = io_loop_create();
	struct test_sqlpool ts;
	test_sqlpool_init(&ts, "test_sqlpool_statement_scan_error");
	ts.conndb->state = SQL_DB_STATE_IDLE;

	bool got_result = FALSE;
	struct sql_statement *stmt = sql_statement_init(ts.pool,
		"SELECT foo FROM bar WHERE foo = ? # trailing comment");
	sql_statement_query(&stmt, test_sql_sqlpool_statement_scan_error_callback,
			    &got_result);
	io_loop_run(ioloop);
	test_assert(got_result);

	sql_unref(&ts.pool);
	io_loop_destroy(&ioloop);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_sql_sqlpool_commit_queue_drain,
		test_sql_sqlpool_commit_s_queue_drain,
		test_sql_sqlpool_abort_queued_commit,
		test_sql_sqlpool_statement_queue_drain,
		test_sql_sqlpool_update_stmt_no_connection,
		test_sql_sqlpool_statement_scan_error,
		NULL
	};
	return test_run(test_functions);
}
