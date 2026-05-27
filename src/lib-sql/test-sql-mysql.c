/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "settings.h"
#include "test-common.h"
#include "sql-api-private.h"

#include <getopt.h>
#include <unistd.h>

extern const struct setting_parser_info mysql_setting_parser_info;

static const char *test_mysql_host = "localhost";
static const char *test_mysql_port = "0";
static const char *test_mysql_user = "";
static const char *test_mysql_password = "";
static const char *test_mysql_dbname = "dovecot_test";

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
		"  num INT, blob_col BLOB"
		")");
}

static void test_sql_mysql(void)
{
	test_begin("test sql mysql api");

	struct ioloop *ioloop = io_loop_create();
	settings_info_register(&mysql_setting_parser_info);

	struct settings_simple set;
	settings_simple_init(&set, (const char *const []) {
		"sql_driver", "mysql",
		"mysql", test_mysql_host,
		"mysql_port", test_mysql_port,
		"mysql_user", test_mysql_user,
		"mysql_password", test_mysql_password,
		"mysql_dbname", test_mysql_dbname,
		NULL,
	});
	struct sql_db *sql = NULL;
	const char *error = NULL;

	sql_drivers_init_without_drivers();
	driver_mysql_init();

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
		i_error("test-sql-mysql: cannot reach the mysql server: %s",
			error);
		sql_unref(&sql);
		driver_mysql_deinit();
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

	/* sql_result_get_values() on a prepared-statement result must
	   return the current row's values, not values left over from an
	   earlier row or an earlier call, and must agree with itself when
	   called twice on the same row. */
	stmt = sql_statement_init(sql, "INSERT INTO test2 VALUES(?,?,?,?)");
	sql_statement_bind_str(stmt, 0, "test_str2");
	sql_statement_bind_uuid(stmt, 1, uuid);
	sql_statement_bind_int64(stmt, 2, 654321);
	sql_statement_bind_binary(stmt, 3, "\x01\x02", 2);
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
	sql_result_unref(cursor);

	stmt = sql_statement_init(sql, "SELECT str, num FROM test2 ORDER BY num");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	const char *const *values = sql_result_get_values(cursor);
	test_assert_strcmp(values[0], "test_str");
	test_assert_strcmp(values[1], "123456");
	/* repeated call on the same row must return the same values */
	values = sql_result_get_values(cursor);
	test_assert_strcmp(values[0], "test_str");
	test_assert_strcmp(values[1], "123456");

	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	values = sql_result_get_values(cursor);
	test_assert_strcmp(values[0], "test_str2");
	test_assert_strcmp(values[1], "654321");

	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
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

	/* mysql binds ? placeholders natively via mysql_stmt_prepare() on
	   query_template as-is (see driver_mysql_statement_query_s()) and
	   never renders the scanned template, so without the
	   template_scan_error check at the shared entry points, a query
	   template the scanner rejects would still be prepared and
	   executed - with no error at all, since mysql itself accepts '#'
	   as a valid line comment. */
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

	/* mysql allows '$' inside an unquoted identifier - dict-sql
	   splices config-supplied field names straight into the template,
	   so a bare '$' there must scan fine. Only a dollar-quote open tag
	   ("$$" or "$tag$") is rejected. */
	stmt = sql_statement_init(sql,
		"SELECT foo AS my$alias FROM bar WHERE foo = ?");
	sql_statement_bind_str(stmt, 0, "value1");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "my$alias");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value1");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
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

	/* same unscannable-template check on the sql_update_stmt() entry
	   point */
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

	/* The '?' inside the quoted string constant 'a?b' is not a bind
	   placeholder; MySQL's own prepared-statement parser agrees, so
	   the query executes fine with one bound value. driver_mysql_execute_stmt()
	   renders the query through sql_statement_get_log_query() before
	   executing it, so this exercises that scan against a live driver,
	   confirming the literal '?' passes through unconsumed. */
	stmt = sql_statement_init(sql, "SELECT foo FROM bar WHERE foo = 'a?b' OR foo = ?");
	sql_statement_bind_str(stmt, 0, "value1");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value1");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
	sql_result_unref(cursor);

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
	driver_mysql_deinit();
	sql_drivers_deinit_without_drivers();
	settings_simple_deinit(&set);
	io_loop_destroy(&ioloop);

	test_end();
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		i_info("test-sql-mysql: skipped (no parameters given)");
		return 0;
	}

	int c;
	while ((c = getopt(argc, argv, "h:P:u:p:d:")) != -1) {
		switch (c) {
		case 'h':
			test_mysql_host = optarg;
			break;
		case 'P':
			test_mysql_port = optarg;
			break;
		case 'u':
			test_mysql_user = optarg;
			break;
		case 'p':
			test_mysql_password = optarg;
			break;
		case 'd':
			test_mysql_dbname = optarg;
			break;
		default:
			i_fatal("Usage: test-sql-mysql "
				"[-h host] [-P port] [-u user] "
				"[-p password] [-d dbname]");
		}
	}

	static void (*const test_functions[])(void) = {
		test_sql_mysql,
		NULL
	};
	return test_run(test_functions);
}
