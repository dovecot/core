/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

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

	struct sql_prepared_statement *prep_stmt =
		sql_prepared_statement_init(sql, "INSERT INTO bar VALUES(?)");
	struct sql_statement *stmt =
		sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "value3");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
	sql_result_unref(cursor);

	stmt = sql_statement_init(sql, "SELECT foo FROM bar WHERE foo = ?");
	sql_statement_bind_str(stmt, 0, "value3");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value3");
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
	test_assert_memcmp(value, "\xFF\xFF\x00\x00\xFF", 5);
	sql_result_unref(cursor);

	prep_stmt = sql_prepared_statement_init(sql, "SELECT foo FROM bar WHERE foo = ?");
	sql_disconnect(sql);
	stmt = sql_statement_init_prepared(prep_stmt);
	sql_statement_bind_str(stmt, 0, "value3");
	cursor = sql_statement_query_s(&stmt);
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value3");
	sql_result_unref(cursor);
	sql_prepared_statement_unref(&prep_stmt);

	sql_unref(&sql);
	driver_sqlite_deinit();
	sql_drivers_deinit_without_drivers();
	settings_simple_deinit(&set);

	test_end();
}

int main(void) {
	static void (*const test_functions[])(void) = {
		test_sql_sqlite,
		NULL
	};
	return test_run(test_functions);
}
