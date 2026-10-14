/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "settings.h"
#include "dict-private.h"
#include "test-common.h"
#include "test-dir.h"

#include <unistd.h>
#include <sys/stat.h>

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
	const char *value = NULL, *error;

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

struct test_dict_file {
	struct settings_simple set;
	struct dict *dict;
};

static void
test_dict_file_init(struct test_dict_file *ctx, const char *path,
		    const char *lock_method)
{
	const char *const settings[] = {
		"dict", "file",
		"dict/file/path", path,
		"dict/file/lock_method", lock_method,
		NULL
	};
	const char *error;

	settings_simple_init(&ctx->set, settings);
	if (dict_init_auto(ctx->set.event, &ctx->dict, &error) <= 0)
		i_fatal("dict_init_auto(%s) failed: %s", path, error);
}

static void test_dict_file_deinit(struct test_dict_file *ctx)
{
	dict_deinit(&ctx->dict);
	settings_simple_deinit(&ctx->set);
}

static void test_dict_file_lookup_missing(struct dict *dict, const char *key)
{
	const struct dict_op_settings set = { };
	const char *value, *error;

	test_assert(dict_lookup(dict, &set, pool_datastack_create(), key,
				&value, &error) == 0);
}

/* Finish the iteration and check that it returned exactly the expected
   key/value pairs. */
static void
test_dict_file_iterate_finish(struct dict_iterate_context **iter,
			      const char *const *expected, int expected_ret)
{
	unsigned int count = 0;
	const char *key, *value, *error;

	while (dict_iterate(*iter, &key, &value)) {
		const char *const *pair = expected;
		while (pair[0] != NULL && strcmp(pair[0], key) != 0)
			pair += 2;
		if (pair[0] == NULL)
			test_failed(t_strdup_printf("Unexpected key %s", key));
		else
			test_assert_strcmp(value, pair[1]);
		count++;
	}
	test_assert(count == str_array_length(expected) / 2);
	test_assert(dict_iterate_deinit(iter, &error) == expected_ret);
}

static struct dict_iterate_context *
test_dict_file_iterate_init(struct dict *dict)
{
	const struct dict_op_settings set = { };

	return dict_iterate_init(dict, &set, DICT_PATH_SHARED,
				 DICT_ITERATE_FLAG_RECURSE);
}

static void test_dict_file_iterate_commit(void)
{
	const struct dict_op_settings op_set = { };
	struct dict_transaction_context *trans;
	struct test_dict_file ctx;
	const char *error;

	test_begin("dict file commit while iterating");
	test_dict_file_init(&ctx, t_strconcat(test_dir_get(),
					      "/iterate-commit", NULL),
			    "dotlock");
	struct dict *dict = ctx.dict;
	test_dict_file_set(dict, DICT_PATH_SHARED"a", "1");
	test_dict_file_set(dict, DICT_PATH_SHARED"b", "1");
	test_dict_file_set(dict, DICT_PATH_SHARED"s", "foo");
	test_dict_file_set(dict, DICT_PATH_SHARED"n", "5");

	struct dict_iterate_context *iter = test_dict_file_iterate_init(dict);
	trans = dict_transaction_begin(dict, &op_set);
	dict_set(trans, DICT_PATH_SHARED"a", "2");
	dict_unset(trans, DICT_PATH_SHARED"b");
	dict_set(trans, DICT_PATH_SHARED"c", "1");
	dict_atomic_inc(trans, DICT_PATH_SHARED"n", 1);
	test_assert(dict_transaction_commit(&trans, &error) == 1);

	trans = dict_transaction_begin(dict, &op_set);
	dict_set(trans, DICT_PATH_SHARED"d", "1");
	dict_atomic_inc(trans, DICT_PATH_SHARED"s", 1);
	test_assert(dict_transaction_commit(&trans, &error) < 0);

	test_dict_file_lookup(dict, DICT_PATH_SHARED"a", "2");
	test_dict_file_lookup_missing(dict, DICT_PATH_SHARED"b");
	test_dict_file_lookup(dict, DICT_PATH_SHARED"c", "1");
	test_dict_file_lookup_missing(dict, DICT_PATH_SHARED"d");
	test_dict_file_lookup(dict, DICT_PATH_SHARED"n", "6");
	test_dict_file_iterate_finish(&iter, (const char *const []) {
		DICT_PATH_SHARED"a", "1",
		DICT_PATH_SHARED"b", "1",
		DICT_PATH_SHARED"n", "5",
		DICT_PATH_SHARED"s", "foo",
		NULL
	}, 0);

	test_dict_file_deinit(&ctx);
	test_end();
}

static void test_dict_file_iterate_replaced_one(const char *lock_method)
{
	struct test_dict_file ctx1, ctx2;
	const char *path;

	path = t_strdup_printf("%s/iterate-replaced-%s", test_dir_get(),
			       lock_method);
	test_dict_file_init(&ctx1, path, lock_method);
	test_dict_file_init(&ctx2, path, lock_method);
	test_dict_file_set(ctx1.dict, DICT_PATH_SHARED"a", "1");

	/* The other dict replaces the file. Lookups see its changes while
	   the iterator keeps returning what it started with. */
	struct dict_iterate_context *iter =
		test_dict_file_iterate_init(ctx1.dict);
	test_dict_file_set(ctx2.dict, DICT_PATH_SHARED"b", "1");
	test_dict_file_lookup(ctx1.dict, DICT_PATH_SHARED"b", "1");
	test_dict_file_iterate_finish(&iter, (const char *const []) {
		DICT_PATH_SHARED"a", "1",
		NULL
	}, 0);

	test_dict_file_deinit(&ctx1);
	test_dict_file_deinit(&ctx2);
}

static void test_dict_file_iterate_replaced(void)
{
	test_begin("dict file replaced while iterating");
	test_dict_file_iterate_replaced_one("dotlock");
	test_dict_file_iterate_replaced_one("fcntl");
	test_end();
}

static void test_dict_file_iterate_replaced_commit_one(const char *lock_method)
{
	struct test_dict_file ctx1, ctx2;
	const char *path;

	path = t_strdup_printf("%s/iterate-replaced-commit-%s",
			       test_dir_get(), lock_method);
	test_dict_file_init(&ctx1, path, lock_method);
	test_dict_file_init(&ctx2, path, lock_method);
	test_dict_file_set(ctx1.dict, DICT_PATH_SHARED"a", "1");

	/* A commit while iterating must include the changes of the file
	   that the other dict wrote. */
	struct dict_iterate_context *iter =
		test_dict_file_iterate_init(ctx1.dict);
	test_dict_file_set(ctx2.dict, DICT_PATH_SHARED"b", "1");
	test_dict_file_set(ctx1.dict, DICT_PATH_SHARED"c", "1");
	test_dict_file_iterate_finish(&iter, (const char *const []) {
		DICT_PATH_SHARED"a", "1",
		NULL
	}, 0);

	test_dict_file_lookup(ctx2.dict, DICT_PATH_SHARED"a", "1");
	test_dict_file_lookup(ctx2.dict, DICT_PATH_SHARED"b", "1");
	test_dict_file_lookup(ctx2.dict, DICT_PATH_SHARED"c", "1");

	test_dict_file_deinit(&ctx1);
	test_dict_file_deinit(&ctx2);
}

static void test_dict_file_iterate_replaced_commit(void)
{
	test_begin("dict file commit after replace while iterating");
	test_dict_file_iterate_replaced_commit_one("dotlock");
	test_dict_file_iterate_replaced_commit_one("fcntl");
	test_end();
}

static int test_dict_file_try_set(struct dict *dict, const char *key)
{
	const struct dict_op_settings op_set = { };
	struct dict_transaction_context *trans;
	const char *error;

	trans = dict_transaction_begin(dict, &op_set);
	dict_set(trans, key, "new");
	return dict_transaction_commit(&trans, &error);
}

static void test_dict_file_read_error(void)
{
	const struct dict_op_settings op_set = { };
	struct test_dict_file ctx;
	struct stat st;
	const char *dir, *path, *value, *error;

	test_begin("dict file read error");
	dir = t_strconcat(test_dir_get(), "/dir", NULL);
	path = t_strconcat(test_dir_get(), "/dict", NULL);
	test_dict_file_init(&ctx, path, "dotlock");
	struct dict *dict = ctx.dict;
	test_dict_file_set(dict, DICT_PATH_SHARED"a", "1");
	struct dict_iterate_context *iter = test_dict_file_iterate_init(dict);

	/* A symlink to a directory opens read-only for dotlocks, and reading
	   it fails with EISDIR. A commit that wrote the dict from what it read
	   would replace the symlink with a new file. */
	if (mkdir(dir, 0700) < 0)
		i_fatal("mkdir(%s) failed: %m", dir);
	i_unlink(path);
	if (symlink(dir, path) < 0)
		i_fatal("symlink(%s) failed: %m", path);

	test_assert(dict_lookup(dict, &op_set, pool_datastack_create(),
				DICT_PATH_SHARED"a", &value, &error) < 0);
	test_assert(test_dict_file_try_set(dict, DICT_PATH_SHARED"a") < 0);
	test_assert(lstat(path, &st) == 0 && S_ISLNK(st.st_mode));

	/* the iterator started before the error still finishes */
	test_dict_file_iterate_finish(&iter, (const char *const []) {
		DICT_PATH_SHARED"a", "1",
		NULL
	}, 0);
	/* an iterator started after it fails */
	iter = test_dict_file_iterate_init(dict);
	test_dict_file_iterate_finish(&iter, (const char *const []) {
		NULL
	}, -1);

	test_dict_file_deinit(&ctx);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dict_escape,
		test_dict_async_lookup,
		test_dict_file_atomic_inc_non_numeric,
		test_dict_file_iterate_commit,
		test_dict_file_iterate_replaced,
		test_dict_file_iterate_replaced_commit,
		test_dict_file_read_error,
		NULL
	};
	int ret;

	test_dir_init("dict");
	dict_driver_register(&dict_driver_file);
	ret = test_run(test_functions);
	dict_driver_unregister(&dict_driver_file);
	return ret;
}
