/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "settings.h"
#include "test-common.h"
#include "sql-api-private.h"

#include <getopt.h>

extern const struct setting_parser_info cassandra_setting_parser_info;

static const char *test_cassandra_host = "127.0.0.1";
static const char *test_cassandra_port = "9042";
static const char *test_cassandra_user = "";
static const char *test_cassandra_password = "";
static const char *test_cassandra_keyspace = "dovecot_test";

/* driver-cassandra doesn't connect with a default keyspace (it uses plain
   cass_session_connect(), not cass_session_connect_keyspace()), so every
   table name used here must be keyspace-qualified. */
static char *test_cassandra_tbl_bar;
static char *test_cassandra_tbl_test2;

struct test_cassandra_async_ctx {
	struct ioloop *ioloop;
	bool done;

	struct sql_result *result;

	bool commit_failed;
	char *commit_error;
};

static void
test_cassandra_query_callback(struct sql_result *result,
			      struct test_cassandra_async_ctx *ctx)
{
	/* the result is unref'd right after this callback returns */
	sql_result_ref(result);
	ctx->result = result;
	ctx->done = TRUE;
	io_loop_stop(ctx->ioloop);
}

/* sql_statement_query_s() is not implemented for cassandra - it
   i_panic()s ("cassandra: sql_statement_query_s() not supported").
   Every statement-based query here goes through the async
   sql_statement_query() instead, pumped synchronously with our own
   ioloop wait. */
static struct sql_result *
test_cassandra_statement_query(struct sql_statement **_stmt)
{
	struct test_cassandra_async_ctx ctx = {
		.ioloop = current_ioloop,
	};

	sql_statement_query(_stmt, test_cassandra_query_callback, &ctx);
	while (!ctx.done)
		io_loop_run(ctx.ioloop);
	return ctx.result;
}

static void
test_cassandra_commit_callback(const struct sql_commit_result *result,
			       struct test_cassandra_async_ctx *ctx)
{
	if (result->error != NULL) {
		ctx->commit_failed = TRUE;
		ctx->commit_error = i_strdup(result->error);
	}
	ctx->done = TRUE;
	io_loop_stop(ctx->ioloop);
}

/* sql_transaction_commit_s() i_panic()s for cassandra whenever a
   transaction holds more than one statement, or any prepared statement -
   the driver comment says plainly "nothing should be using this - don't
   bother implementing". The async sql_transaction_commit() has no such
   restriction, so every transaction here commits through it, pumped
   synchronously with our own ioloop wait. */
static int
test_cassandra_transaction_commit(struct sql_transaction_context **_ctx,
				  const char **error_r)
{
	struct test_cassandra_async_ctx ctx = {
		.ioloop = current_ioloop,
	};

	sql_transaction_commit(_ctx, test_cassandra_commit_callback, &ctx);
	while (!ctx.done)
		io_loop_run(ctx.ioloop);
	*error_r = t_strdup(ctx.commit_error);
	i_free(ctx.commit_error);
	return ctx.commit_failed ? -1 : 0;
}

/* Returns FALSE with *error_r set if the very first query fails because
   the server is unreachable, instead of test_assert()ing it and letting
   the caller run every later query against a dead connection too. */
static bool setup_database(struct sql_db *sql, const char **error_r)
{
	struct sql_result *result;

	result = sql_query_s(sql, t_strdup_printf(
		"DROP TABLE IF EXISTS %s", test_cassandra_tbl_bar));
	if (sql_result_next_row(result) == SQL_RESULT_NEXT_ERROR) {
		*error_r = t_strdup(sql_result_get_error(result));
		sql_result_unref(result);
		return FALSE;
	}
	sql_result_unref(result);

	result = sql_query_s(sql, t_strdup_printf(
		"DROP TABLE IF EXISTS %s", test_cassandra_tbl_test2));
	test_assert(sql_result_next_row(result) != SQL_RESULT_NEXT_ERROR);
	sql_result_unref(result);

	result = sql_query_s(sql, t_strdup_printf(
		"CREATE TABLE %s (foo TEXT PRIMARY KEY)",
		test_cassandra_tbl_bar));
	test_assert(sql_result_next_row(result) != SQL_RESULT_NEXT_ERROR);
	sql_result_unref(result);

	result = sql_query_s(sql, t_strdup_printf(
		"CREATE TABLE %s ("
		"  str TEXT PRIMARY KEY, uuid UUID,"
		"  num BIGINT, blob_col BLOB"
		")", test_cassandra_tbl_test2));
	test_assert(sql_result_next_row(result) != SQL_RESULT_NEXT_ERROR);
	sql_result_unref(result);
	return TRUE;
}

static void
test_cassandra_assert_bar_row(struct sql_db *sql, const char *key)
{
	struct sql_result *result = sql_query_s(sql, t_strdup_printf(
		"SELECT foo FROM %s WHERE foo = '%s'",
		test_cassandra_tbl_bar, key));

	test_assert(sql_result_next_row(result) == SQL_RESULT_NEXT_OK);
	test_assert_strcmp(sql_result_get_field_value(result, 0), key);
	test_assert(sql_result_next_row(result) == SQL_RESULT_NEXT_LAST);
	sql_result_unref(result);
}

static void test_sql_cassandra(void)
{
	test_begin("test sql cassandra api");

	test_cassandra_tbl_bar =
		i_strdup_printf("%s.bar", test_cassandra_keyspace);
	test_cassandra_tbl_test2 =
		i_strdup_printf("%s.test2", test_cassandra_keyspace);

	struct ioloop *ioloop = io_loop_create();
	settings_info_register(&cassandra_setting_parser_info);

	struct settings_simple set;
	settings_simple_init(&set, (const char *const []) {
		"sql_driver", "cassandra",
		"cassandra_hosts", test_cassandra_host,
		"cassandra_port", test_cassandra_port,
		"cassandra_keyspace", test_cassandra_keyspace,
		"cassandra_user", test_cassandra_user,
		"cassandra_password", test_cassandra_password,
		/* a single-node test cluster has no meaningful "local"
		   datacenter for local-quorum to reason about; "one" is
		   the consistency a single-node SimpleStrategy keyspace
		   actually supports. */
		"cassandra_read_consistency", "one",
		"cassandra_write_consistency", "one",
		"cassandra_delete_consistency", "one",
		NULL,
	});
	struct sql_db *sql = NULL;
	const char *error = NULL;

	sql_drivers_init_without_drivers();
	driver_cassandra_init();

	if (sql_init_auto(set.event, &sql, &error) <= 0)
		i_fatal("%s", error);
	test_assert(sql != NULL && error == NULL);
	if (!setup_database(sql, &error)) {
		/* the server is unreachable - bail out here instead of
		   running the rest of the test against a dead connection,
		   where every query returns an error result with no rows
		   or fields. */
		i_error("test-cql-cassandra: cannot reach the cassandra "
			"server: %s", error);
		sql_unref(&sql);
		driver_cassandra_deinit();
		sql_drivers_deinit_without_drivers();
		settings_simple_deinit(&set);
		io_loop_destroy(&ioloop);
		i_free(test_cassandra_tbl_bar);
		i_free(test_cassandra_tbl_test2);
		test_end();
		return;
	}

	/* insert data using plain sql_update() - two statements in one
	   transaction, which cassandra sends as a logged BATCH */
	struct sql_transaction_context *t = sql_transaction_begin(sql);
	sql_update(t, t_strdup_printf(
		"INSERT INTO %s (foo) VALUES('plain1')",
		test_cassandra_tbl_bar));
	sql_update(t, t_strdup_printf(
		"INSERT INTO %s (foo) VALUES('plain2')",
		test_cassandra_tbl_bar));
	test_assert(test_cassandra_transaction_commit(&t, &error) == 0);
	test_assert(error == NULL);

	test_cassandra_assert_bar_row(sql, "plain1");
	test_cassandra_assert_bar_row(sql, "plain2");

	/* multi-row iteration: read every row back without assuming any
	   particular order (CQL has no ORDER BY on a partition key) */
	struct sql_result *cursor = sql_query_s(sql, t_strdup_printf(
		"SELECT foo FROM %s", test_cassandra_tbl_bar));
	unsigned int row_count = 0;
	bool got_plain1 = FALSE, got_plain2 = FALSE;
	int ret;
	while ((ret = sql_result_next_row(cursor)) > 0) {
		row_count++;
		const char *value = sql_result_get_field_value(cursor, 0);
		if (strcmp(value, "plain1") == 0)
			got_plain1 = TRUE;
		else if (strcmp(value, "plain2") == 0)
			got_plain2 = TRUE;
	}
	test_assert(ret >= 0);
	test_assert_ucmp(row_count, ==, 2);
	test_assert(got_plain1 && got_plain2);
	sql_result_unref(cursor);

	/* insert data using statements (non-prepared). A non-prepared
	   cassandra statement never reaches cass_statement_bind_*(): its
	   ? placeholders are substituted with escaped literal values by
	   the generic sql_statement_get_query(), so this exercises the
	   escaping path rather than a native bind. */
	t = sql_transaction_begin(sql);
	struct sql_statement *stmt = sql_statement_init(sql, t_strdup_printf(
		"INSERT INTO %s (foo) VALUES(?)", test_cassandra_tbl_bar));
	sql_statement_bind_str(stmt, 0, "stmt1");
	sql_update_stmt(t, &stmt);
	stmt = sql_statement_init(sql, t_strdup_printf(
		"INSERT INTO %s (foo) VALUES(?)", test_cassandra_tbl_bar));
	sql_statement_bind_str(stmt, 0, "stmt2");
	sql_update_stmt(t, &stmt);
	test_assert(test_cassandra_transaction_commit(&t, &error) == 0);
	test_assert(error == NULL);

	test_cassandra_assert_bar_row(sql, "stmt1");
	test_cassandra_assert_bar_row(sql, "stmt2");

	/* insert data using prepared statements - this is the path that
	   actually reaches cass_prepared_bind() + cass_statement_bind_*(),
	   i.e. a native bind rather than literal substitution */
	t = sql_transaction_begin(sql);
	struct sql_prepared_statement *prep_stmt = sql_prepared_statement_init(
		sql, t_strdup_printf("INSERT INTO %s (foo) VALUES(?)",
				     test_cassandra_tbl_bar));
	stmt = sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "prep1");
	sql_update_stmt(t, &stmt);
	stmt = sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "prep2");
	sql_update_stmt(t, &stmt);
	test_assert(test_cassandra_transaction_commit(&t, &error) == 0);
	test_assert(error == NULL);
	sql_prepared_statement_unref(&prep_stmt);

	test_cassandra_assert_bar_row(sql, "prep1");
	test_cassandra_assert_bar_row(sql, "prep2");

	/* multi-type prepared statement: bind str, uuid, int64 and binary,
	   then read every value back and confirm it round-tripped */
	prep_stmt = sql_prepared_statement_init(sql, t_strdup_printf(
		"INSERT INTO %s (str, uuid, num, blob_col) VALUES(?,?,?,?)",
		test_cassandra_tbl_test2));
	stmt = sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "test_str");
	guid_128_t uuid;
	ret = guid_128_from_uuid_string(
		"426b3821-3c6c-4ed7-a936-ec8d664c53d0", uuid);
	i_assert(ret == 0);
	sql_statement_bind_uuid(stmt, 1, uuid);
	sql_statement_bind_int64(stmt, 2, 123456);
	sql_statement_bind_binary(stmt, 3, "\xFF\xFF\x00\x00\xFF", 5);
	cursor = test_cassandra_statement_query(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
	sql_result_unref(cursor);
	sql_prepared_statement_unref(&prep_stmt);

	cursor = sql_query_s(sql, t_strdup_printf(
		"SELECT * FROM %s WHERE str = 'test_str'",
		test_cassandra_tbl_test2));
	bool got_row = sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK;
	test_assert(got_row);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 4);
	int idx_str = sql_result_find_field(cursor, "str");
	int idx_uuid = sql_result_find_field(cursor, "uuid");
	int idx_num = sql_result_find_field(cursor, "num");
	int idx_blob = sql_result_find_field(cursor, "blob_col");
	test_assert(idx_str >= 0 && idx_uuid >= 0 &&
		    idx_num >= 0 && idx_blob >= 0);
	/* the row and every index must be valid before any of it is
	   dereferenced below - a failed query (wrong keyspace, missing
	   table, ...) must produce assert failures here, not a crash.
	   sql_result_get_values() in particular returns a plain array with
	   no bounds checking of its own. */
	if (got_row && idx_str >= 0 && idx_uuid >= 0 &&
	    idx_num >= 0 && idx_blob >= 0) {
		test_assert_strcmp(sql_result_get_field_value(cursor, idx_str),
				   "test_str");
		test_assert_strcmp(sql_result_get_field_value(cursor, idx_uuid),
				   "426b3821-3c6c-4ed7-a936-ec8d664c53d0");
		test_assert_strcmp(sql_result_get_field_value(cursor, idx_num),
				   "123456");
		size_t size;
		const unsigned char *value =
			sql_result_get_field_value_binary(cursor, idx_blob, &size);
		test_assert_ucmp(size, ==, 5);
		test_assert_memcmp(value, size, "\xFF\xFF\x00\x00\xFF", 5);
		const char *const *values = sql_result_get_values(cursor);
		test_assert_strcmp(values[idx_str], "test_str");
		test_assert_strcmp(values[idx_num], "123456");
	}
	sql_result_unref(cursor);

	/* a zero-length binary bind must round-trip as an empty blob, not
	   as CQL NULL */
	prep_stmt = sql_prepared_statement_init(sql, t_strdup_printf(
		"INSERT INTO %s (str, uuid, num, blob_col) VALUES(?,?,?,?)",
		test_cassandra_tbl_test2));
	stmt = sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "empty_blob");
	sql_statement_bind_uuid(stmt, 1, uuid);
	sql_statement_bind_int64(stmt, 2, 0);
	sql_statement_bind_binary(stmt, 3, "", 0);
	cursor = test_cassandra_statement_query(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
	sql_result_unref(cursor);
	sql_prepared_statement_unref(&prep_stmt);

	cursor = sql_query_s(sql, t_strdup_printf(
		"SELECT blob_col FROM %s WHERE str = 'empty_blob'",
		test_cassandra_tbl_test2));
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	size_t empty_blob_size;
	const unsigned char *empty_blob_value =
		sql_result_get_field_value_binary(cursor, 0, &empty_blob_size);
	test_assert_ucmp(empty_blob_size, ==, 0);
	test_assert(empty_blob_value != NULL);
	sql_result_unref(cursor);

	/* test that failures are handled properly: "extra_col" doesn't
	   exist on bar, so the server rejects the whole batch */
	t = sql_transaction_begin(sql);
	sql_update(t, t_strdup_printf(
		"INSERT INTO %s (foo, extra_col) VALUES('should_not_exist', 'x')",
		test_cassandra_tbl_bar));
	test_assert(test_cassandra_transaction_commit(&t, &error) == -1);
	test_assert(error != NULL);

	/* test CQL syntax error in transaction */
	error = NULL;
	t = sql_transaction_begin(sql);
	sql_update(t, "NOT VALID CQL SYNTAX");
	test_assert(test_cassandra_transaction_commit(&t, &error) == -1);
	test_assert(error != NULL);

	/* test statement with syntax error */
	stmt = sql_statement_init(sql, "NOT VALID CQL ?");
	sql_statement_bind_str(stmt, 0, "test");
	cursor = test_cassandra_statement_query(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_ERROR);
	test_assert(sql_result_get_error(cursor) != NULL);
	sql_result_unref(cursor);

	/* test statement referencing an undefined column */
	error = NULL;
	t = sql_transaction_begin(sql);
	stmt = sql_statement_init(sql, t_strdup_printf(
		"INSERT INTO %s (foo, extra_col) VALUES(?, ?)",
		test_cassandra_tbl_bar));
	sql_statement_bind_str(stmt, 0, "should_not_exist2");
	sql_statement_bind_str(stmt, 1, "extra");
	sql_update_stmt(t, &stmt);
	test_assert(test_cassandra_transaction_commit(&t, &error) == -1);
	test_assert(error != NULL);

	/* Aborting a statement must not double-unref its pool. A double
	   pool_unref() on an alloconly pool frees the arena holding its
	   own refcount, so the second unref corrupts already-freed memory
	   without failing any assertion here - only a memory checker such
	   as valgrind can catch it. This block is that coverage, not an
	   assertion. */
	struct sql_statement *abort_stmt = sql_statement_init(sql, t_strdup_printf(
		"INSERT INTO %s (foo) VALUES(?)", test_cassandra_tbl_bar));
	sql_statement_bind_str(abort_stmt, 0, "aborted");
	sql_statement_abort(&abort_stmt);

	sql_unref(&sql);
	driver_cassandra_deinit();
	sql_drivers_deinit_without_drivers();
	settings_simple_deinit(&set);
	io_loop_destroy(&ioloop);
	i_free(test_cassandra_tbl_bar);
	i_free(test_cassandra_tbl_test2);

	test_end();
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		i_info("test-cql-cassandra: skipped (no parameters given)");
		return 0;
	}

	int c;
	while ((c = getopt(argc, argv, "h:P:u:p:k:")) != -1) {
		switch (c) {
		case 'h':
			test_cassandra_host = optarg;
			break;
		case 'P':
			test_cassandra_port = optarg;
			break;
		case 'u':
			test_cassandra_user = optarg;
			break;
		case 'p':
			test_cassandra_password = optarg;
			break;
		case 'k':
			test_cassandra_keyspace = optarg;
			break;
		default:
			i_fatal("Usage: test-cql-cassandra "
				"[-h host] [-P port] [-u user] "
				"[-p password] [-k keyspace]");
		}
	}

	static void (*const test_functions[])(void) = {
		test_sql_cassandra,
		NULL
	};
	return test_run(test_functions);
}
