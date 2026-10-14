/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "settings.h"
#include "dict-private.h"
#include "test-common.h"

static void test_dict_escape(void)
{
	static const char *input[] = {
		"", "",
		"foo", "foo",
		"foo\\", "foo\\\\",
		"foo\\bar", "foo\\\\bar",
		"\\bar", "\\\\bar",
		"foo/", "foo\\|",
		"foo/bar", "foo\\|bar",
		"/bar", "\\|bar",
		"////", "\\|\\|\\|\\|",
		"/", "\\|"
	};
	unsigned int i;

	test_begin("dict escape");
	for (i = 0; i < N_ELEMENTS(input); i += 2) {
		test_assert(strcmp(dict_escape_string(input[i]), input[i+1]) == 0);
		test_assert(strcmp(dict_unescape_string(input[i+1]), input[i]) == 0);
	}
	test_assert(strcmp(dict_unescape_string("x\\"), "x") == 0);
	test_assert(strcmp(dict_unescape_string("\\"), "") == 0);
	test_end();
}

struct test_dict {
	struct dict dict;

	dict_lookup_callback_t *callback;
	void *context;
};

static void
test_dict_lookup_async_delayed(struct dict *_dict,
			       const struct dict_op_settings *set ATTR_UNUSED,
			       const char *key ATTR_UNUSED,
			       dict_lookup_callback_t *callback, void *context)
{
	struct test_dict *dict = container_of(_dict, struct test_dict, dict);

	dict->callback = callback;
	dict->context = context;
}

static void
test_dict_lookup_callback(const struct dict_lookup_result *result,
			  bool *called)
{
	test_assert_cmp(result->ret, ==, 0);
	*called = TRUE;
}

static void test_dict_async_lookup(void)
{
	struct test_dict dict;
	const struct dict_op_settings set = { };
	const struct dict_lookup_result result = { .ret = 0 };
	bool called = FALSE;

	test_begin("dict async lookup");
	i_zero(&dict);
	dict.dict.refcount = 1;
	dict.dict.v.lookup_async = test_dict_lookup_async_delayed;
	dict.dict.event = event_create(NULL);

	test_assert(!dict_have_async_operations(&dict.dict));
	dict_lookup_async(&dict.dict, &set, DICT_PATH_SHARED"key",
			  test_dict_lookup_callback, &called);
	/* The lookup keeps a dict reference, so it must be visible as a
	   pending async operation. Otherwise dict_deinit() would silently
	   leave the dict alive. */
	test_assert(dict_have_async_operations(&dict.dict));
	test_assert(!called);

	dict.callback(&result, dict.context);
	test_assert(called);
	test_assert(!dict_have_async_operations(&dict.dict));
	test_assert_cmp(dict.dict.refcount, ==, 1);

	event_unref(&dict.dict.event);
	test_end();
}

static void test_dict_file_set(struct dict *dict, const char *key,
			       const char *value)
{
	const struct dict_op_settings set = { };
	struct dict_transaction_context *t;
	const char *error;

	t = dict_transaction_begin(dict, &set);
	dict_set(t, key, value);
	if (dict_transaction_commit(&t, &error) < 0)
		i_fatal("dict_transaction_commit() failed: %s", error);
}

static void test_dict_file_lookup(struct dict *dict, const char *key,
				  const char *expected_value)
{
	const struct dict_op_settings set = { };
	const char *value, *error;

	test_assert(dict_lookup(dict, &set, pool_datastack_create(), key,
				&value, &error) == 1);
	test_assert_strcmp(value, expected_value);
}

static void test_dict_file_atomic_inc_non_numeric_one(const char *lock_method)
{
	const struct dict_op_settings set = { };
	struct dict_transaction_context *t;
	struct settings_simple test_set;
	struct dict *dict;
	const char *error;

	i_unlink_if_exists(".test-dict-file");
	settings_simple_init(&test_set, (const char *const []) {
		"dict", "file",
		"dict/file/path", ".test-dict-file",
		"dict/file/lock_method", lock_method,
		NULL,
	});
	if (dict_init_auto(test_set.event, &dict, &error) <= 0)
		i_fatal("dict_init_auto() failed: %s", error);

	test_dict_file_set(dict, DICT_PATH_SHARED"num", "1");
	test_dict_file_set(dict, DICT_PATH_SHARED"str", "foo");

	/* The failing atomic_inc must not leave the earlier changes
	   applied in memory. */
	t = dict_transaction_begin(dict, &set);
	dict_set(t, DICT_PATH_SHARED"new", "bar");
	dict_atomic_inc(t, DICT_PATH_SHARED"num", 10);
	dict_atomic_inc(t, DICT_PATH_SHARED"str", 1);
	test_assert(dict_transaction_commit(&t, &error) < 0);

	test_dict_file_lookup(dict, DICT_PATH_SHARED"num", "1");
	test_dict_file_lookup(dict, DICT_PATH_SHARED"str", "foo");
	const char *value;
	test_assert(dict_lookup(dict, &set, pool_datastack_create(),
				DICT_PATH_SHARED"new", &value, &error) == 0);

	/* The next successful commit must not write the failed changes
	   either. */
	test_dict_file_set(dict, DICT_PATH_SHARED"other", "baz");
	dict_deinit(&dict);
	if (dict_init_auto(test_set.event, &dict, &error) <= 0)
		i_fatal("dict_init_auto() failed: %s", error);
	test_dict_file_lookup(dict, DICT_PATH_SHARED"num", "1");
	test_dict_file_lookup(dict, DICT_PATH_SHARED"other", "baz");
	test_assert(dict_lookup(dict, &set, pool_datastack_create(),
				DICT_PATH_SHARED"new", &value, &error) == 0);
	dict_deinit(&dict);

	settings_simple_deinit(&test_set);
	i_unlink(".test-dict-file");
}

static void test_dict_file_atomic_inc_non_numeric(void)
{
	test_begin("dict-file atomic_inc non-numeric");
	test_dict_file_atomic_inc_non_numeric_one("dotlock");
	test_dict_file_atomic_inc_non_numeric_one("fcntl");
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dict_escape,
		test_dict_async_lookup,
		test_dict_file_atomic_inc_non_numeric,
		NULL
	};
	int ret;

	dict_driver_register(&dict_driver_file);
	ret = test_run(test_functions);
	dict_driver_unregister(&dict_driver_file);
	return ret;
}
