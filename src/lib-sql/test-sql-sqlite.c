/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "settings.h"
#include "test-common.h"
#include "sql-api-private.h"

static const char sql_create_db[] =
"CREATE TABLE bar(\n"
"  foo VARCHAR(255)\n"
");\n"
"CREATE TABLE test2(\n"
"   str VARCHAR(255), uuid VARCHAR(36),\n"
"   num INT, blob BLOB\n"
")\n";

static void setup_database(struct sql_db *sql)
{
	sql_disconnect(sql);
	i_unlink_if_exists("test-database.db");
	sql_exec(sql, sql_create_db);
}

static void test_sql_sqlite(void)
{
	test_begin("test sql api");

	struct settings_simple set;
	settings_simple_init(&set, (const char *const []) {
		"sql_driver", "sqlite",
		"sqlite_path", "test-database.db",
		"sqlite_journal_mode", "wal",
		NULL,
	});
	struct sql_db *sql = NULL;
	const char *error = NULL;

	sql_drivers_init_without_drivers();
	driver_sqlite_init();

	if (sql_init_auto(set.event, &sql, &error) <= 0)
		i_fatal("%s", error);
	test_assert(sql != NULL && error == NULL);
	setup_database(sql);

	/* insert data */
	struct sql_transaction_context *t = sql_transaction_begin(sql);
	sql_update(t, "INSERT INTO bar VALUES(\"value1\")");
	sql_update(t, "INSERT INTO bar VALUES(\"value2\")");
	test_assert(sql_transaction_commit_s(&t, &error) == 0);

	struct sql_result *cursor = sql_query_s(sql, "SELECT foo FROM bar");

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
	struct sql_statement *stmt = sql_statement_init(sql, "INSERT INTO bar VALUES(?)");
	sql_statement_bind_str(stmt, 0, "value1");
	sql_update_stmt(t, &stmt);
	stmt = sql_statement_init(sql, "INSERT INTO bar VALUES(?)");
	sql_statement_bind_str(stmt, 0, "value2");
	sql_update_stmt(t, &stmt);
	test_assert(sql_transaction_commit_s(&t, &error) == 0);
	cursor = sql_query_s(sql, "SELECT foo FROM bar");

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
	cursor = sql_query_s(sql, "SELECT foo FROM bar");

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

	stmt = sql_statement_init(sql, "INSERT INTO test2 VALUES(?,?,?,?)");
	sql_statement_bind_str(stmt, 0, "test_str");
	guid_128_t uuid;
	int ret = guid_128_from_uuid_string("426b3821-3c6c-4ed7-a936-ec8d664c53d0", uuid);
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
	test_assert_strcmp(sql_result_get_field_value(cursor, 1), "426b3821-3c6c-4ed7-a936-ec8d664c53d0");
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
	stmt = sql_statement_init(sql, "SELECT blob FROM test2 "
				  "WHERE str = ? AND blob IS NOT NULL");
	sql_statement_bind_str(stmt, 0, "empty_blob");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	size_t empty_blob_size;
	(void)sql_result_get_field_value_binary(cursor, 0, &empty_blob_size);
	test_assert_ucmp(empty_blob_size, ==, 0);
	sql_result_unref(cursor);

	prep_stmt = sql_prepared_statement_init(sql, "SELECT foo FROM bar WHERE foo = ?");
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
	sql_update(t, "INSERT INTO bar VALUES(\"value1\", 2)");
	sql_update(t, "INSERT INTO bar VALUES(\"value2\", 3)");
	test_assert(sql_transaction_commit_s(&t, &error) == -1);
	test_assert_strcmp(error, "table bar has 1 columns but 2 values were supplied "
			   "(rc=1, extended_rc=1, errno=0)");

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

	/* An unscannable template must fail through the shared
	   template_scan_error check before it ever reaches the driver.
	   driver_sqlite_statement_query_s() hands query_template to
	   sqlite3_prepare_v2() as-is, so without that check the '#' below
	   would be passed straight to sqlite - which fails it with its own
	   syntax error, not the scanner's, since sqlite has no idea a
	   comment there is unsafe for locating '?' placeholders. */
	stmt = sql_statement_init(sql,
		"SELECT foo FROM bar WHERE foo = ? # trailing comment");
	sql_statement_bind_str(stmt, 0, "value1");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_ERROR);
	test_assert_strcmp(sql_result_get_error(cursor),
		"query template has a '#' comment outside a quoted string - "
		"comments are not allowed in a query template; bind "
		"placeholders after it cannot be located reliably");
	sql_result_unref(cursor);

	/* same check on the sql_update_stmt() entry point */
	error = NULL;
	t = sql_transaction_begin(sql);
	stmt = sql_statement_init(sql, "INSERT INTO bar VALUES(? # bad)");
	sql_statement_bind_str(stmt, 0, "value3");
	sql_update_stmt(t, &stmt);
	test_assert(sql_transaction_commit_s(&t, &error) == -1);
	test_assert_strcmp(error,
		"query template has a '#' comment outside a quoted string - "
		"comments are not allowed in a query template; bind "
		"placeholders after it cannot be located reliably");

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

	/* sql_statement_get_log_query() must expand every bound value by
	   default, and hide only the field(s) marked via
	   sql_statement_set_no_log_expanded_value_field(), leaving every
	   other bound value expanded. */
	stmt = sql_statement_init(sql, "INSERT INTO test2 (str, num) VALUES (?, ?)");
	sql_statement_bind_str(stmt, 0, "plain");
	sql_statement_bind_int64(stmt, 1, 7);
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "INSERT INTO test2 (str, num) VALUES ('plain', 7)");
	sql_statement_set_no_log_expanded_value_field(stmt, 0);
	test_assert_strcmp(sql_statement_get_log_query(stmt),
			   "INSERT INTO test2 (str, num) VALUES (?, 7)");
	sql_statement_abort(&stmt);

	sql_unref(&sql);
	driver_sqlite_deinit();
	sql_drivers_deinit_without_drivers();
	settings_simple_deinit(&set);

	test_end();
}

static void test_sql_sqlite_errors(void)
{
	test_begin("test sql api errors");

	struct settings_simple set;
	settings_simple_init(&set, (const char *const []) {
		"sql_driver", "sqlite",
		"sqlite_path", "test-database-errors.db",
		"sqlite_journal_mode", "wal",
		NULL,
	});
	struct sql_db *sql = NULL;
	const char *error = NULL;

	sql_drivers_init_without_drivers();
	driver_sqlite_init();

	if (sql_init_auto(set.event, &sql, &error) <= 0)
		i_fatal("%s", error);
	sql_disconnect(sql);
	i_unlink_if_exists("test-database-errors.db");
	sql_exec(sql, "CREATE TABLE pk(id INTEGER PRIMARY KEY)");
	sql_exec(sql, "INSERT INTO pk VALUES(1)");

	/* SQLite's own message is reported, not just the generic text for the
	   result code, which would be "SQL logic error" for all of these. */
	struct sql_result *result =
		sql_query_s(sql, "SELECT x FROM nosuchtable");
	test_assert(sql_result_next_row(result) < 0);
	error = sql_result_get_error(result);
	test_assert(strstr(error, "no such table: nosuchtable") != NULL);
	test_assert(strstr(error, "rc=1") != NULL);
	sql_result_unref(result);

	result = sql_query_s(sql, "SELCT bogus");
	test_assert(sql_result_next_row(result) < 0);
	/* driver_sqlite_error_result's find_field, find_field_value and
	   get_values must fail cleanly on a failed query, not crash
	   through a NULL vfunc. */
	test_assert(sql_result_find_field(result, "x") == -1);
	test_assert(sql_result_find_field_value(result, "x") == NULL);
	test_assert(sql_result_get_values(result) == NULL);
	error = sql_result_get_error(result);
	test_assert(strstr(error, "syntax error") != NULL);
	sql_result_unref(result);

	result = sql_query_s(sql, "SELECT nosuchcolumn FROM pk");
	test_assert(sql_result_next_row(result) < 0);
	error = sql_result_get_error(result);
	test_assert(strstr(error, "no such column: nosuchcolumn") != NULL);
	sql_result_unref(result);

	/* A failing sqlite3_step() reports the extended result code, which
	   says which kind of constraint failed (SQLITE_CONSTRAINT_PRIMARYKEY
	   rather than plain SQLITE_CONSTRAINT). */
	result = sql_query_s(sql, "INSERT INTO pk VALUES(1)");
	test_assert(sql_result_next_row(result) < 0);
	error = sql_result_get_error(result);
	test_assert(strstr(error, "UNIQUE constraint failed: pk.id") != NULL);
	test_assert(strstr(error, "rc=19") != NULL);
	test_assert(strstr(error, "extended_rc=1555") != NULL);
	sql_result_unref(result);

	/* The transaction keeps the whole error of the statement that failed,
	   not just its result code. */
	struct sql_transaction_context *t = sql_transaction_begin(sql);
	sql_update(t, "INSERT INTO pk VALUES(1)");
	test_assert(sql_transaction_commit_s(&t, &error) < 0);
	test_assert(strstr(error, "UNIQUE constraint failed: pk.id") != NULL);
	test_assert(strstr(error, "extended_rc=1555") != NULL);

	/* Errors that driver-sqlite generates itself have no SQLite message or
	   extended code, so they fall back to the text for the result code. */
	result = sql_query_s(sql, "");
	test_assert(sql_result_next_row(result) < 0);
	error = sql_result_get_error(result);
	test_assert(strstr(error, "rc=21") != NULL);
	test_assert(strstr(error, "extended_rc=21") != NULL);
	sql_result_unref(result);

	sql_unref(&sql);
	driver_sqlite_deinit();
	sql_drivers_deinit_without_drivers();
	settings_simple_deinit(&set);
	i_unlink_if_exists("test-database-errors.db");

	test_end();
}

int main(void) {
	static void (*const test_functions[])(void) = {
		test_sql_sqlite,
		test_sql_sqlite_errors,
		NULL
	};
	return test_run(test_functions);
}
