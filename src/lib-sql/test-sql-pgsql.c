/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "settings.h"
#include "test-common.h"
#include "sql-api-private.h"

#include <getopt.h>

extern const struct setting_parser_info pgsql_setting_parser_info;

static const char *test_pgsql_host = "localhost";
static const char *test_pgsql_user = "";
static const char *test_pgsql_password = "";
static const char *test_pgsql_dbname = "dovecot_test";
/* Only set via -U. An unroutable address is environment-dependent (some
   networks return ICMP unreachable for TEST-NET-1 instead of black-holing
   it), so the connect-timeout tests only run when the caller opts in. */
static const char *test_pgsql_unroutable_host = "";
/* Set once the first test can't reach the server, so later tests that
   need the same connection skip instead of cascading through asserts
   against a dead one. */
static bool test_pgsql_unreachable = FALSE;

static void setup_database(struct sql_db *sql)
{
	sql_exec(sql, "DROP TABLE IF EXISTS bar");
	sql_exec(sql, "DROP TABLE IF EXISTS test2");
	sql_exec(sql,
		"CREATE TABLE bar("
		"  foo VARCHAR(255)"
		")");
	sql_exec(sql,
		"CREATE TABLE test2("
		"  str VARCHAR(255), uuid VARCHAR(36),"
		"  num INT, blob_col BYTEA"
		")");
}

static void test_sql_pgsql(void)
{
	test_begin("test sql pgsql api");

	struct ioloop *ioloop = io_loop_create();
	settings_info_register(&pgsql_setting_parser_info);

	struct settings_simple set;
	settings_simple_init(&set, (const char *const []) {
		"sql_driver", "pgsql",
		"pgsql", test_pgsql_host,
		"pgsql_host", test_pgsql_host,
		"pgsql_parameters/user", test_pgsql_user,
		"pgsql_parameters/password", test_pgsql_password,
		"pgsql_parameters/dbname", test_pgsql_dbname,
		NULL,
	});
	struct sql_db *sql = NULL;
	const char *error = NULL;

	sql_drivers_init_without_drivers();
	driver_pgsql_init();

	if (sql_init_auto(set.event, &sql, &error) <= 0)
		i_fatal("%s", error);
	test_assert(sql != NULL && error == NULL);
	setup_database(sql);

	/* insert data */
	struct sql_transaction_context *t = sql_transaction_begin(sql);
	sql_update(t, "INSERT INTO bar VALUES('value1')");
	sql_update(t, "INSERT INTO bar VALUES('value2')");
	if (sql_transaction_commit_s(&t, &error) < 0) {
		/* the server is unreachable - bail out here instead of
		   running the rest of the test against a dead connection,
		   where every query returns an error result with no rows
		   or fields. */
		i_error("test-sql-pgsql: cannot reach the pgsql server: %s",
			error);
		test_pgsql_unreachable = TRUE;
		sql_unref(&sql);
		driver_pgsql_deinit();
		sql_drivers_deinit_without_drivers();
		settings_simple_deinit(&set);
		io_loop_destroy(&ioloop);
		test_end();
		return;
	}

	struct sql_result *cursor =
		sql_query_s(sql, "SELECT foo FROM bar ORDER BY foo");

	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value1");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value2");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);

	sql_result_unref(cursor);

	/* reset bar */
	sql_exec(sql, "DELETE FROM bar");

	/* insert data using statements */
	t = sql_transaction_begin(sql);
	struct sql_statement *stmt =
		sql_statement_init(sql, "INSERT INTO bar VALUES(?)");
	sql_statement_bind_str(stmt, 0, "value1");
	sql_update_stmt(t, &stmt);
	stmt = sql_statement_init(sql, "INSERT INTO bar VALUES(?)");
	sql_statement_bind_str(stmt, 0, "value2");
	sql_update_stmt(t, &stmt);
	test_assert(sql_transaction_commit_s(&t, &error) == 0);
	cursor = sql_query_s(sql, "SELECT foo FROM bar ORDER BY foo");

	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value1");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value2");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);

	sql_result_unref(cursor);

	/* reset bar */
	sql_exec(sql, "DELETE FROM bar");

	/* insert data using prepared statements */
	t = sql_transaction_begin(sql);
	struct sql_prepared_statement *prep_stmt =
		sql_prepared_statement_init(sql, "INSERT INTO bar VALUES(?)");
	stmt = sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "value1");
	sql_update_stmt(t, &stmt);
	stmt = sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "value2");
	sql_update_stmt(t, &stmt);
	test_assert(sql_transaction_commit_s(&t, &error) == 0);
	cursor = sql_query_s(sql, "SELECT foo FROM bar ORDER BY foo");

	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value1");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value2");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);

	sql_result_unref(cursor);
	sql_prepared_statement_unref(&prep_stmt);

	/* test multi-type statement with query */
	stmt = sql_statement_init(sql, "INSERT INTO test2 VALUES(?,?,?,?)");
	sql_statement_bind_str(stmt, 0, "test_str");
	guid_128_t uuid;
	int ret = guid_128_from_uuid_string(
		"426b3821-3c6c-4ed7-a936-ec8d664c53d0", uuid);
	i_assert(ret == 0);
	sql_statement_bind_uuid(stmt, 1, uuid);
	sql_statement_bind_int64(stmt, 2, 123456);
	sql_statement_bind_binary(stmt, 3, "\xFF\xFF\x00\x00\xFF", 5);
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
	sql_result_unref(cursor);

	stmt = sql_statement_init(sql, "SELECT * FROM test2");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 4);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "str");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "test_str");
	test_assert_strcmp(sql_result_get_field_name(cursor, 1), "uuid");
	test_assert_strcmp(sql_result_get_field_value(cursor, 1),
			  "426b3821-3c6c-4ed7-a936-ec8d664c53d0");
	test_assert_strcmp(sql_result_get_field_name(cursor, 2), "num");
	test_assert_strcmp(sql_result_get_field_value(cursor, 2), "123456");
	size_t size;
	const unsigned char *value =
		sql_result_get_field_value_binary(cursor, 3, &size);
	test_assert_ucmp(size, ==, 5);
	test_assert_memcmp(value, size, "\xFF\xFF\x00\x00\xFF", 5);
	sql_result_unref(cursor);

	/* a zero-length binary bind must not panic */
	stmt = sql_statement_init(sql, "INSERT INTO test2 VALUES(?,?,?,?)");
	sql_statement_bind_str(stmt, 0, "empty_blob");
	sql_statement_bind_uuid(stmt, 1, uuid);
	sql_statement_bind_int64(stmt, 2, 0);
	sql_statement_bind_binary(stmt, 3, "", 0);
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
	sql_result_unref(cursor);

	/* the bound value must round-trip as an empty blob, not SQL NULL */
	stmt = sql_statement_init(sql, "SELECT blob_col FROM test2 "
				  "WHERE str = ? AND blob_col IS NOT NULL");
	sql_statement_bind_str(stmt, 0, "empty_blob");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	size_t empty_blob_size;
	(void)sql_result_get_field_value_binary(cursor, 0, &empty_blob_size);
	test_assert_ucmp(empty_blob_size, ==, 0);
	sql_result_unref(cursor);

	/* test disconnect + reconnect with prepared statement */
	prep_stmt = sql_prepared_statement_init(sql,
		"SELECT foo FROM bar WHERE foo = ?");
	sql_disconnect(sql);
	stmt = sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "value2");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value2");
	sql_result_unref(cursor);
	sql_prepared_statement_unref(&prep_stmt);

	/* test that failures are handled properly */
	t = sql_transaction_begin(sql);
	sql_update(t, "INSERT INTO bar VALUES('value1', 2)");
	sql_update(t, "INSERT INTO bar VALUES('value2', 3)");
	test_assert(sql_transaction_commit_s(&t, &error) == -1);
	test_assert(error != NULL);

	/* test SQL syntax error in transaction */
	error = NULL;
	t = sql_transaction_begin(sql);
	sql_update(t, "NOT VALID SQL SYNTAX");
	test_assert(sql_transaction_commit_s(&t, &error) == -1);
	test_assert(error != NULL);

	/* test statement with syntax error */
	stmt = sql_statement_init(sql, "NOT VALID SQL ?");
	sql_statement_bind_str(stmt, 0, "test");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_ERROR);
	test_assert(sql_result_get_error(cursor) != NULL);
	sql_result_unref(cursor);

	/* test statement with too many values for table */
	error = NULL;
	t = sql_transaction_begin(sql);
	stmt = sql_statement_init(sql, "INSERT INTO bar VALUES(?, ?)");
	sql_statement_bind_str(stmt, 0, "value1");
	sql_statement_bind_str(stmt, 1, "extra");
	sql_update_stmt(t, &stmt);
	test_assert(sql_transaction_commit_s(&t, &error) == -1);
	test_assert(error != NULL);

	/* Aborting a statement must not double-unref its pool. A double
	   pool_unref() on an alloconly pool frees the arena holding its own
	   refcount, so the second unref corrupts already-freed memory
	   without failing any assertion here - only a memory checker such
	   as valgrind can catch it. This block is that coverage, not an
	   assertion. */
	struct sql_statement *abort_stmt =
		sql_statement_init(sql, "INSERT INTO bar VALUES(?)");
	sql_statement_bind_str(abort_stmt, 0, "aborted");
	sql_statement_abort(&abort_stmt);

	sql_unref(&sql);
	driver_pgsql_deinit();
	sql_drivers_deinit_without_drivers();
	settings_simple_deinit(&set);
	io_loop_destroy(&ioloop);

	test_end();
}

/* Exercise convert_query_template()'s $n conversion against a live
   server: a placeholder next to a PostgreSQL cast, and a '?' inside a
   quoted string literal that must not be converted to a parameter. */
static void test_sql_pgsql_placeholder_scan(void)
{
	if (test_pgsql_unreachable) {
		i_info("test-sql-pgsql: placeholder scan test skipped "
		       "(pgsql server unreachable)");
		return;
	}

	test_begin("test sql pgsql placeholder scan");

	struct ioloop *ioloop = io_loop_create();

	struct settings_simple set;
	settings_simple_init(&set, (const char *const []) {
		"sql_driver", "pgsql",
		"pgsql", test_pgsql_host,
		"pgsql_host", test_pgsql_host,
		"pgsql_parameters/user", test_pgsql_user,
		"pgsql_parameters/password", test_pgsql_password,
		"pgsql_parameters/dbname", test_pgsql_dbname,
		NULL,
	});
	struct sql_db *sql = NULL;
	const char *error = NULL;

	sql_drivers_init_without_drivers();
	driver_pgsql_init();

	if (sql_init_auto(set.event, &sql, &error) <= 0)
		i_fatal("%s", error);
	test_assert(sql != NULL && error == NULL);

	/* a placeholder immediately next to a PostgreSQL cast is converted
	   to $1 */
	struct sql_statement *stmt =
		sql_statement_init(sql, "SELECT ?::text AS v");
	sql_statement_bind_str(stmt, 0, "value1");
	struct sql_result *cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value1");
	sql_result_unref(cursor);

	/* a '?' inside a quoted string literal is not converted to a
	   parameter; only the real placeholder afterwards becomes $1 */
	stmt = sql_statement_init(sql,
		"SELECT 'a?b'::text AS lit, ?::text AS v");
	sql_statement_bind_str(stmt, 0, "value2");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "a?b");
	test_assert_strcmp(sql_result_get_field_value(cursor, 1), "value2");
	sql_result_unref(cursor);

	/* An unscannable template must fail through the shared
	   template_scan_error check before it ever reaches the driver.
	   sql_template_scan() stops at the first unquoted '$' it rejects,
	   so the real placeholder after the dollar-quoted "$$dq$$" below
	   is never added to stmt->placeholders - without the check,
	   convert_query_template() converts only the first '?' to $1 and
	   leaves the second one as a literal '?' in the query text, which
	   libpq then rejects with its own syntax/parameter error instead
	   of the scanner's. */
	stmt = sql_statement_init(sql,
		"SELECT ?::text AS v WHERE $$dq$$::text = 'dq' "
		"AND ?::text = 'x'");
	sql_statement_bind_str(stmt, 0, "value1");
	sql_statement_bind_str(stmt, 1, "value2");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_ERROR);
	test_assert_strcmp(sql_result_get_error(cursor),
		"query template has a dollar-quoted string outside a "
		"quoted string - a dollar-quoted string is not allowed "
		"in a query template; bind placeholders after it cannot "
		"be located reliably");
	sql_result_unref(cursor);

	/* same check on the sql_update_stmt() entry point */
	struct sql_transaction_context *t2 = sql_transaction_begin(sql);
	stmt = sql_statement_init(sql,
		"INSERT INTO bar VALUES($$dq$$::text)");
	sql_update_stmt(t2, &stmt);
	const char *dq_error = NULL;
	test_assert(sql_transaction_commit_s(&t2, &dq_error) == -1);
	test_assert_strcmp(dq_error,
		"query template has a dollar-quoted string outside a "
		"quoted string - a dollar-quoted string is not allowed "
		"in a query template; bind placeholders after it cannot "
		"be located reliably");

	sql_unref(&sql);
	driver_pgsql_deinit();
	sql_drivers_deinit_without_drivers();
	settings_simple_deinit(&set);
	io_loop_destroy(&ioloop);

	test_end();
}

/* connect_timeout is enforced, and a user-supplied
   pgsql_parameters/connect_timeout overrides the injected default.
   Gated behind -U because it depends on an environment that black-holes
   the unroutable address rather than answering with ICMP unreachable. */
static void test_sql_pgsql_connect_timeout(void)
{
	if (test_pgsql_unroutable_host[0] == '\0') {
		i_info("test-sql-pgsql: connect timeout tests skipped "
		       "(no -U <unroutable-addr> given)");
		return;
	}

	test_begin("test sql pgsql connect timeout (default)");
	{
		struct ioloop *ioloop = io_loop_create();
		settings_info_register(&pgsql_setting_parser_info);

		struct settings_simple set;
		settings_simple_init(&set, (const char *const []) {
			"sql_driver", "pgsql",
			"pgsql", test_pgsql_unroutable_host,
			"pgsql_host", test_pgsql_unroutable_host,
			NULL,
		});
		struct sql_db *sql = NULL;
		const char *error = NULL;

		sql_drivers_init_without_drivers();
		driver_pgsql_init();

		if (sql_init_auto(set.event, &sql, &error) <= 0)
			i_fatal("%s", error);
		test_assert(sql != NULL && error == NULL);

		/* sql_init_auto() does not connect - the connect happens on
		   the first query, so time that rather than sql_init_auto().
		   Two connect attempts (see below) each log a "Connect
		   failed" error; tell the test framework to allow them. */
		test_expect_errors(2);
		struct timeval tv_start, tv_end;
		i_gettimeofday(&tv_start);
		struct sql_result *result = sql_query_s(sql, "SELECT 1");
		i_gettimeofday(&tv_end);
		long long elapsed_msecs = timeval_diff_msecs(&tv_end, &tv_start);
		test_expect_no_more_errors();

		test_assert(sql_result_next_row(result) == SQL_RESULT_NEXT_ERROR);
		test_assert(sql_result_get_error(result) != NULL);
		/* SQL_CONNECT_TIMEOUT_SECS is 5, but the very first query
		   through a fresh sqlpool with no live connections makes two
		   connect attempts: sqlpool_find_available_connection() fails,
		   sees every connection disconnected, resets connect_delay and
		   retries once before giving up (driver-sqlpool.c). That is
		   sqlpool's own retry-when-all-disconnected logic, unrelated to
		   this driver's connect_timeout injection, so the bound here is
		   two attempts wide. Pre-change this blocks indefinitely either
		   way. */
		test_assert_ucmp(elapsed_msecs, >=, 9000);
		test_assert_ucmp(elapsed_msecs, <, 14000);
		sql_result_unref(result);

		sql_unref(&sql);
		driver_pgsql_deinit();
		sql_drivers_deinit_without_drivers();
		settings_simple_deinit(&set);
		io_loop_destroy(&ioloop);
	}
	test_end();

	test_begin("test sql pgsql connect timeout (operator override)");
	{
		struct ioloop *ioloop = io_loop_create();
		settings_info_register(&pgsql_setting_parser_info);

		struct settings_simple set;
		settings_simple_init(&set, (const char *const []) {
			"sql_driver", "pgsql",
			"pgsql", test_pgsql_unroutable_host,
			"pgsql_host", test_pgsql_unroutable_host,
			"pgsql_parameters/connect_timeout", "2",
			NULL,
		});
		struct sql_db *sql = NULL;
		const char *error = NULL;

		sql_drivers_init_without_drivers();
		driver_pgsql_init();

		if (sql_init_auto(set.event, &sql, &error) <= 0)
			i_fatal("%s", error);
		test_assert(sql != NULL && error == NULL);

		test_expect_errors(2);
		struct timeval tv_start, tv_end;
		i_gettimeofday(&tv_start);
		struct sql_result *result = sql_query_s(sql, "SELECT 1");
		i_gettimeofday(&tv_end);
		long long elapsed_msecs = timeval_diff_msecs(&tv_end, &tv_start);
		test_expect_no_more_errors();

		test_assert(sql_result_next_row(result) == SQL_RESULT_NEXT_ERROR);
		/* Same doubling as above (two connect attempts), scaled to the
		   2s override. */
		test_assert_ucmp(elapsed_msecs, >=, 3500);
		test_assert_ucmp(elapsed_msecs, <, 6000);
		sql_result_unref(result);

		sql_unref(&sql);
		driver_pgsql_deinit();
		sql_drivers_deinit_without_drivers();
		settings_simple_deinit(&set);
		io_loop_destroy(&ioloop);
	}
	test_end();
}

/* The default statement_timeout is injected via
   "options", it survives merging with an operator-supplied "options"
   string, and a timed-out query fails once (not twice through sqlpool's
   retry-on-failure). */
static void test_sql_pgsql_statement_timeout(void)
{
	if (test_pgsql_unreachable) {
		i_info("test-sql-pgsql: statement_timeout tests skipped "
		       "(pgsql server unreachable)");
		return;
	}

	test_begin("test sql pgsql statement_timeout default");
	{
		struct ioloop *ioloop = io_loop_create();
		settings_info_register(&pgsql_setting_parser_info);

		struct settings_simple set;
		settings_simple_init(&set, (const char *const []) {
			"sql_driver", "pgsql",
			"pgsql", test_pgsql_host,
			"pgsql_host", test_pgsql_host,
			"pgsql_parameters/user", test_pgsql_user,
			"pgsql_parameters/password", test_pgsql_password,
			"pgsql_parameters/dbname", test_pgsql_dbname,
			NULL,
		});
		struct sql_db *sql = NULL;
		const char *error = NULL;

		sql_drivers_init_without_drivers();
		driver_pgsql_init();

		if (sql_init_auto(set.event, &sql, &error) <= 0)
			i_fatal("%s", error);
		test_assert(sql != NULL && error == NULL);

		/* SQL_QUERY_TIMEOUT_SECS is 60; PostgreSQL normalizes the
		   60000ms GUC value to "1min" in SHOW output. */
		struct sql_result *cursor =
			sql_query_s(sql, "SHOW statement_timeout");
		test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
		test_assert_strcmp(sql_result_get_field_value(cursor, 0), "1min");
		sql_result_unref(cursor);

		sql_unref(&sql);
		driver_pgsql_deinit();
		sql_drivers_deinit_without_drivers();
		settings_simple_deinit(&set);
		io_loop_destroy(&ioloop);
	}
	test_end();

	/* This is the discriminating test: an implementation that pushes
	   "options" as a plain keyword pair (rather than scanning and
	   merging) passes the default-options test above but loses
	   statement_timeout entirely here, because libpq resolves a
	   duplicate "options" keyword last-wins on the whole string. */
	test_begin("test sql pgsql statement_timeout merges with options");
	{
		struct ioloop *ioloop = io_loop_create();
		settings_info_register(&pgsql_setting_parser_info);

		struct settings_simple set;
		settings_simple_init(&set, (const char *const []) {
			"sql_driver", "pgsql",
			"pgsql", test_pgsql_host,
			"pgsql_host", test_pgsql_host,
			"pgsql_parameters/user", test_pgsql_user,
			"pgsql_parameters/password", test_pgsql_password,
			"pgsql_parameters/dbname", test_pgsql_dbname,
			"pgsql_parameters/options", "-c search_path=public",
			NULL,
		});
		struct sql_db *sql = NULL;
		const char *error = NULL;

		sql_drivers_init_without_drivers();
		driver_pgsql_init();

		if (sql_init_auto(set.event, &sql, &error) <= 0)
			i_fatal("%s", error);
		test_assert(sql != NULL && error == NULL);

		struct sql_result *cursor =
			sql_query_s(sql, "SHOW statement_timeout");
		test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
		test_assert_strcmp(sql_result_get_field_value(cursor, 0), "1min");
		sql_result_unref(cursor);

		cursor = sql_query_s(sql, "SHOW search_path");
		test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
		test_assert_strcmp(sql_result_get_field_value(cursor, 0), "public");
		sql_result_unref(cursor);

		sql_unref(&sql);
		driver_pgsql_deinit();
		sql_drivers_deinit_without_drivers();
		settings_simple_deinit(&set);
		io_loop_destroy(&ioloop);
	}
	test_end();

	test_begin("test sql pgsql statement_timeout enforcement, no sqlpool doubling");
	{
		struct ioloop *ioloop = io_loop_create();
		settings_info_register(&pgsql_setting_parser_info);

		struct settings_simple set;
		settings_simple_init(&set, (const char *const []) {
			"sql_driver", "pgsql",
			"pgsql", test_pgsql_host,
			"pgsql_host", test_pgsql_host,
			"pgsql_parameters/user", test_pgsql_user,
			"pgsql_parameters/password", test_pgsql_password,
			"pgsql_parameters/dbname", test_pgsql_dbname,
			"pgsql_parameters/options", "-c statement_timeout=2000",
			NULL,
		});
		struct sql_db *sql = NULL;
		const char *error = NULL;

		sql_drivers_init_without_drivers();
		driver_pgsql_init();

		if (sql_init_auto(set.event, &sql, &error) <= 0)
			i_fatal("%s", error);
		test_assert(sql != NULL && error == NULL);

		/* sql_init_auto() returns the sqlpool-wrapped db (pgsql is
		   always SQL_DB_FLAG_POOLED), so this also exercises
		   driver_sqlpool_query_s()'s retry-on-failed_try_retry path.
		   Without the 57014 fix the 2s server-side cancellation is
		   retried once, roughly doubling the wall clock to ~4s. */
		struct timeval tv_start, tv_end;
		i_gettimeofday(&tv_start);
		struct sql_result *cursor =
			sql_query_s(sql, "SELECT pg_sleep(10)");
		i_gettimeofday(&tv_end);
		long long elapsed_msecs = timeval_diff_msecs(&tv_end, &tv_start);

		test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_ERROR);
		test_assert_strcmp(sql_result_get_error(cursor), "Query timed out");
		test_assert_ucmp(elapsed_msecs, >=, 1500);
		test_assert_ucmp(elapsed_msecs, <, 4000);
		sql_result_unref(cursor);

		sql_unref(&sql);
		driver_pgsql_deinit();
		sql_drivers_deinit_without_drivers();
		settings_simple_deinit(&set);
		io_loop_destroy(&ioloop);
	}
	test_end();
}

static void test_sql_pgsql_fatal_error_does_not_leak(void)
{
	if (test_pgsql_unreachable) {
		i_info("test-sql-pgsql: fatal_error leak test skipped "
		       "(pgsql server unreachable)");
		return;
	}

	test_begin("test sql pgsql fatal_error does not leak into next query");

	struct ioloop *ioloop = io_loop_create();
	settings_info_register(&pgsql_setting_parser_info);

	struct settings_simple set;
	settings_simple_init(&set, (const char *const []) {
		"sql_driver", "pgsql",
		"pgsql", test_pgsql_host,
		"pgsql_host", test_pgsql_host,
		"pgsql_parameters/user", test_pgsql_user,
		"pgsql_parameters/password", test_pgsql_password,
		"pgsql_parameters/dbname", test_pgsql_dbname,
		NULL,
	});
	struct sql_db *sql = NULL;
	const char *error = NULL;

	sql_drivers_init_without_drivers();
	driver_pgsql_init();

	if (sql_init_auto(set.event, &sql, &error) <= 0)
		i_fatal("%s", error);
	test_assert(sql != NULL && error == NULL);

	sql_result_unref(sql_query_s(sql, "DROP TABLE IF EXISTS stale_fatal_error"));
	sql_result_unref(sql_query_s(sql,
		"CREATE TABLE stale_fatal_error(foo VARCHAR(255))"));

	/* A query that fails with PGRES_FATAL_ERROR, followed by next_row()
	   on the failed result - the same sequence passdb-sql/userdb-sql
	   always run. result_finish() has already classified this result
	   and returned the connection to IDLE before next_row() runs. */
	struct sql_result *bad = sql_query_s(sql,
		"SELECT nonexistent_col FROM stale_fatal_error");
	test_assert(sql_result_next_row(bad) == SQL_RESULT_NEXT_ERROR);
	sql_result_unref(bad);

	/* A single-row transaction right after must commit successfully and
	   insert exactly one row - not fail due to a stale fatal_error
	   inherited from the query above. */
	struct sql_transaction_context *t = sql_transaction_begin(sql);
	sql_update(t, "INSERT INTO stale_fatal_error VALUES('txn')");
	test_assert(sql_transaction_commit_s(&t, &error) == 0);

	struct sql_result *cnt = sql_query_s(sql,
		"SELECT count(*) FROM stale_fatal_error WHERE foo = 'txn'");
	test_assert(sql_result_next_row(cnt) == SQL_RESULT_NEXT_OK);
	test_assert_strcmp(sql_result_get_field_value(cnt, 0), "1");
	sql_result_unref(cnt);

	/* Poison fatal_error again, then a plain sql_query_s() INSERT.
	   sql_init_auto() wraps pgsql in sqlpool unless the event already
	   belongs to one, so this also exercises
	   driver_sqlpool_query_s()'s retry-on-failed_try_retry path: if the
	   INSERT were spuriously marked failed+failed_try_retry, sqlpool
	   would retry it and the row would land twice. */
	struct sql_result *bad2 = sql_query_s(sql,
		"SELECT nonexistent_col FROM stale_fatal_error");
	test_assert(sql_result_next_row(bad2) == SQL_RESULT_NEXT_ERROR);
	sql_result_unref(bad2);

	struct sql_result *ins = sql_query_s(sql,
		"INSERT INTO stale_fatal_error VALUES('direct')");
	sql_result_unref(ins);

	struct sql_result *cnt2 = sql_query_s(sql,
		"SELECT count(*) FROM stale_fatal_error WHERE foo = 'direct'");
	test_assert(sql_result_next_row(cnt2) == SQL_RESULT_NEXT_OK);
	test_assert_strcmp(sql_result_get_field_value(cnt2, 0), "1");
	sql_result_unref(cnt2);

	sql_unref(&sql);
	driver_pgsql_deinit();
	sql_drivers_deinit_without_drivers();
	settings_simple_deinit(&set);
	io_loop_destroy(&ioloop);

	test_end();
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		i_info("test-sql-pgsql: skipped (no parameters given)");
		return 0;
	}

	int c;
	while ((c = getopt(argc, argv, "h:u:p:d:U:")) != -1) {
		switch (c) {
		case 'h':
			test_pgsql_host = optarg;
			break;
		case 'u':
			test_pgsql_user = optarg;
			break;
		case 'p':
			test_pgsql_password = optarg;
			break;
		case 'd':
			test_pgsql_dbname = optarg;
			break;
		case 'U':
			test_pgsql_unroutable_host = optarg;
			break;
		default:
			i_fatal("Usage: test-sql-pgsql "
				"[-h host] [-u user] "
				"[-p password] [-d dbname] "
				"[-U unroutable-addr]");
		}
	}

	static void (*const test_functions[])(void) = {
		test_sql_pgsql,
		test_sql_pgsql_placeholder_scan,
		test_sql_pgsql_connect_timeout,
		test_sql_pgsql_statement_timeout,
		test_sql_pgsql_fatal_error_does_not_leak,
		NULL
	};
	return test_run(test_functions);
}
