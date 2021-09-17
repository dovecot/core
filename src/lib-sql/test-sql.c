/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "sql-api.h"
#include "driver-test.h"

static struct sql_db *setup_sql(void)
{
	const struct sql_settings set = {
		.driver = "sqlite",
		.connect_string = "",
	};
	struct sql_db *sql = NULL;
	const char *error = NULL;

	sql_drivers_init();
	sql_driver_test_register();

	test_assert(sql_init_full(&set, &sql, &error) == 0 &&
		    sql != NULL &&
		    error == NULL);

	test_assert(sql_connect(sql) == 0);
	sql_disconnect(sql);
	return sql;
}

static void deinit_sql(struct sql_db **_sql)
{
	struct sql_db *sql = *_sql;
	if (sql == NULL)
		return;
	*_sql = NULL;

	sql_driver_test_clear_expected_results(sql);
	sql_unref(&sql);

	sql_driver_test_unregister();
	sql_drivers_deinit();
}

#define setup_result_1(sql) \
	struct test_driver_result_set rset_1 = { \
		.rows = 2, \
		.cols = 1, \
		.col_names = (const char *[]){"foo", NULL}, \
		.row_data = (const char **[]){ \
			(const char*[]){"value1", NULL}, \
			(const char*[]){"value2", NULL}, \
		}, \
	}; \
	struct test_driver_result result_1 = { \
		.nqueries = 1, \
		.queries = (const char *[]){"SELECT foo FROM bar"}, \
		.result = &rset_1 \
	}; \
	sql_driver_test_add_expected_result(sql, &result_1);

static void test_result_1(struct sql_result *cursor)
{
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value1");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_OK);
	test_assert_ucmp(sql_result_get_fields_count(cursor), ==, 1);
	test_assert_strcmp(sql_result_get_field_name(cursor, 0), "foo");
	test_assert_strcmp(sql_result_get_field_value(cursor, 0), "value2");
	test_assert(sql_result_next_row(cursor) == SQL_RESULT_NEXT_LAST);
}

static void test_sql_api(void)
{
	test_begin("sql api");

	struct sql_db *sql = setup_sql();
	setup_result_1(sql);
	struct sql_result *cursor = sql_query_s(sql, "SELECT foo FROM bar");

	test_result_1(cursor);

	sql_result_unref(cursor);

	deinit_sql(&sql);

	test_end();
}

static void test_sql_stmt_api(void)
{
	test_begin("sql statement api");

	struct sql_db *sql = setup_sql();
	setup_result_1(sql);

	struct sql_statement *stmt =
		sql_statement_init(sql, "SELECT foo FROM bar");
	struct sql_result *cursor = sql_statement_query_s(&stmt);

	test_result_1(cursor);

	sql_result_unref(cursor);

	deinit_sql(&sql);
	test_end();
}

static void test_sql_stmt_prepared_api(void)
{
	test_begin("sql prepared statement api");

	struct sql_db *sql = setup_sql();
	setup_result_1(sql);

	struct sql_prepared_statement *prep_stmt =
		sql_prepared_statement_init(sql, "SELECT foo FROM bar");
	struct sql_statement *stmt =
		sql_statement_init_prepared(prep_stmt);
	sql_prepared_statement_unref(&prep_stmt);
	struct sql_result *cursor = sql_statement_query_s(&stmt);

	test_result_1(cursor);

	sql_result_unref(cursor);

	deinit_sql(&sql);
	test_end();
}

int main(void) {
	static void (*const test_functions[])(void) = {
		test_sql_api,
		test_sql_stmt_api,
		test_sql_stmt_prepared_api,
		NULL
	};
	return test_run(test_functions);
}
