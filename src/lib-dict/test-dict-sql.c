#include "lib.h"
#include "test-lib.h"
#include "sql-api.h"
#include "dict.h"
#include "dict-private.h"
#include "dict-sql.h"
#include "dict-sql-private.h"
#include "driver-test.h"

static void test_setup(struct dict **dict_r)
{
	const char *error = NULL;
	struct dict_settings set = {
		.username = "testuser",
		.base_dir = "."
	};
	struct dict *dict = NULL;

	if (dict_init("mysql:" DICT_SRC_DIR "/dict.conf", &set, &dict, &error) < 0)
		i_fatal("cannot initialize dict: %s", error);

	*dict_r = dict;
}

static void test_teardown(struct dict **_dict)
{
	struct dict *dict = *_dict;
	*_dict = NULL;
	if (dict != NULL) {
		dict_deinit(&dict);
	}
}

static void test_set_expected(struct dict *_dict,
			      const struct test_driver_result *result)
{
	struct sql_dict *dict =
		(struct sql_dict *)_dict;

	sql_driver_test_add_expected_result(dict->db, result);
}

static void test_lookup_one(void)
{
	const char *value = NULL, *error = NULL;
	struct test_driver_result_set rset = {
		.rows = 1,
		.cols = 1,
		.col_names = (const char *[]){"value", NULL},
		.row_data = (const char **[]){(const char*[]){"one", NULL}},
	};
	struct test_driver_result res = {
		.nqueries = 1,
		.queries = (const char *[]){"SELECT value FROM table WHERE a = 'hello' AND b = 'world'", NULL},
		.result = &rset,
	};
	struct dict *dict;
	pool_t pool = pool_datastack_create();

	test_begin("dict lookup one");
	test_setup(&dict);

	test_set_expected(dict, &res);

	test_assert(dict_lookup(dict, pool, "shared/dictmap/hello/world", &value, &error) == 1);
	test_assert(value != NULL && strcmp(value, "one") == 0);
        if (error != NULL)
                i_error("dict_lookup failed: %s", error);
	test_teardown(&dict);
	test_end();
}

static void test_atomic_inc(void)
{
	const char *error;
	struct test_driver_result res = {
		.nqueries = 2,
		.queries = (const char *[]){
			"UPDATE counters SET value=value+128 WHERE class = 'global' AND name = 'counter'",
			"UPDATE quota SET bytes=bytes+128,count=count+1 WHERE username = 'testuser'",
			NULL},
		.result = NULL,
	};
	struct dict *dict;

	test_begin("dict atomic inc");
	test_setup(&dict);

	test_set_expected(dict, &res);

	struct dict_transaction_context *ctx = dict_transaction_begin(dict);
	dict_atomic_inc(ctx, "shared/counters/global/counter", 128);
	test_assert(dict_transaction_commit(&ctx, &error) == 0);
        if (error != NULL)
                i_error("dict_transaction_commit failed: %s", error);
	error = NULL;
	ctx = dict_transaction_begin(dict);
	dict_atomic_inc(ctx, "priv/quota/bytes", 128);
	dict_atomic_inc(ctx, "priv/quota/count", 1);
	test_assert(dict_transaction_commit(&ctx, &error) == 0);
        if (error != NULL)
                i_error("dict_transaction_commit failed: %s", error);
	test_teardown(&dict);
	test_end();
}

static void test_set(void)
{
	const char *error;
	struct test_driver_result res = {
		.affected_rows = 1,
		.nqueries = 2,
		.queries = (const char *[]){
			"INSERT INTO counters (value,class,name) VALUES (128,'global','counter') ON DUPLICATE KEY UPDATE value=128",
			"INSERT INTO quota (bytes,count,username) VALUES (128,1,'testuser') ON DUPLICATE KEY UPDATE bytes=128,count=1",
			NULL},
		.result = NULL,
	};
	struct dict *dict;

	test_begin("dict set");
	test_setup(&dict);

	test_set_expected(dict, &res);

	struct dict_transaction_context *ctx = dict_transaction_begin(dict);
	dict_set(ctx, "shared/counters/global/counter", "128");
	test_assert(dict_transaction_commit(&ctx, &error) == 1);
        if (error != NULL)
                i_error("dict_transaction_commit failed: %s", error);
	error = NULL;
	ctx = dict_transaction_begin(dict);
	dict_set(ctx, "priv/quota/bytes", "128");
	dict_set(ctx, "priv/quota/count", "1");
	test_assert(dict_transaction_commit(&ctx, &error) == 1);
        if (error != NULL)
                i_error("dict_transaction_commit failed: %s", error);
	test_teardown(&dict);
	test_end();
}

static void test_unset(void)
{
	const char *error;
	struct test_driver_result res = {
		.affected_rows = 1,
		.nqueries = 3,
		.queries = (const char *[]){
			"DELETE FROM counters WHERE class = 'global' AND name = 'counter'",
			"DELETE FROM quota WHERE username = 'testuser'",
			"DELETE FROM quota WHERE username = 'testuser'",
			NULL},
		.result = NULL,
	};
	struct dict *dict;

	test_begin("dict unset");
	test_setup(&dict);

	test_set_expected(dict, &res);

	struct dict_transaction_context *ctx = dict_transaction_begin(dict);
	dict_unset(ctx, "shared/counters/global/counter");
	test_assert(dict_transaction_commit(&ctx, &error) == 1);
	if (error != NULL)
                i_error("dict_transaction_commit failed: %s", error);
	error = NULL;
	ctx = dict_transaction_begin(dict);
	dict_unset(ctx, "priv/quota/bytes");
	dict_unset(ctx, "priv/quota/count");
	test_assert(dict_transaction_commit(&ctx, &error) == 1);
        if (error != NULL)
                i_error("dict_transaction_commit failed: %s", error);
	test_teardown(&dict);
	test_end();
}

static void test_iterate(void)
{
	const char *key = NULL, *value = NULL, *error;
	struct test_driver_result_set rset = {
		.rows = 5,
		.cols = 2,
		.col_names = (const char *[]){"value", "name", NULL},
		.row_data = (const char **[]){
			(const char*[]){"one", "counter", NULL},
			(const char*[]){"two", "counter", NULL},
			(const char*[]){"three", "counter", NULL},
			(const char*[]){"four", "counter", NULL},
			(const char*[]){"five", "counter", NULL},
		},
	};
	struct test_driver_result res = {
		.nqueries = 1,
		.queries = (const char *[]){
			"SELECT value,name FROM counters WHERE class = 'global' AND name = 'counter'",
			NULL},
		.result = &rset,
	};
	struct dict *dict;

	test_begin("dict iterate");
	test_setup(&dict);

	test_set_expected(dict, &res);

	struct dict_iterate_context *iter =
		dict_iterate_init(dict, "shared/counters/global/counter",
				  DICT_ITERATE_FLAG_EXACT_KEY);

	size_t idx = 0;
	while(dict_iterate(iter, &key, &value)) {
		i_assert(idx < rset.rows);
		test_assert_idx(strcmp(key, "shared/counters/global/counter") == 0 &&
				strcmp(value, rset.row_data[idx][0]) == 0, idx);
		idx++;
	}

	test_assert(idx == rset.rows);
	test_assert(dict_iterate_deinit(&iter, &error) == 0);
        if (error != NULL)
                i_error("dict_iterate_deinit failed: %s", error);
	error = NULL;

	res.queries = (const char*[]){
		"SELECT value,name FROM counters WHERE class = 'global' AND name LIKE '%' AND name NOT LIKE '%/%'",
		NULL
	};

	res.cur = 0;
	res.result->cur = 0;

	test_set_expected(dict, &res);

	iter = dict_iterate_init(dict, "shared/counters/global/", 0);

	idx = 0;

	while(dict_iterate(iter, &key, &value)) {
		i_assert(idx < rset.rows);
		test_assert_idx(strcmp(key, "shared/counters/global/counter") == 0 &&
				strcmp(value, rset.row_data[idx][0]) == 0, idx);
		idx++;
	}

	test_assert(idx == rset.rows);
	test_assert(dict_iterate_deinit(&iter, &error) == 0);
	if (error != NULL)
		i_error("dict_iterate_deinit failed: %s", error);
	test_teardown(&dict);
	test_end();
}

int main(void) {
	sql_drivers_init();
	sql_driver_test_register();
	dict_sql_register();

	static void (*const test_functions[])(void) = {
		test_lookup_one,
		test_atomic_inc,
		test_set,
		test_unset,
		test_iterate,
		NULL
	};

	int ret = test_run(test_functions);

	dict_sql_unregister();
	sql_driver_test_unregister();
	sql_drivers_deinit();

	return ret;
}
