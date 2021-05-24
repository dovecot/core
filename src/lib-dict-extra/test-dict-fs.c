#include <errno.h>
#include <sys/stat.h>
#include "lib.h"
#include "unlink-directory.h"
#include "test-common.h"
#include "dict-private.h"

static void test_dict_set_get(struct dict *dict, const char *key,
			     const char *value)
{
	const char *got_value, *error;
	struct dict_op_settings set = {
		.username = "testuser",
	};
	struct dict_transaction_context *t = dict_transaction_begin(dict, &set);
	dict_set(t, key, value);
	if (dict_transaction_commit(&t, &error) < 0)
		i_fatal("dict_transaction_commit(%s) failed: %s", key, error);
	if (dict_lookup(dict, &set, pool_datastack_create(), key, &got_value,
			&error) < 0)
		i_fatal("dict_lookup(%s) failed: %s", key, error);
	test_assert_strcmp(got_value, value);
}

static bool test_file_exists(const char *path)
{
	struct stat st;
	if (stat(path, &st) < 0) {
		if (ENOTFOUND(errno)) return FALSE;
		i_fatal("stat(%s) failed: %m", path);
	}
	return TRUE;
}

static void test_dict_fs_set_get(void)
{
	test_begin("dict-fs get/set");
	const char *error;
	struct dict *dict;
	struct dict_settings set = {
		.base_dir = ".",
	};
	if (dict_init("fs:posix:prefix=.test-dict/", &set, &dict, &error) < 0)
		i_fatal("dict_init() failed: %s", error);

	/* shared paths */
	struct {
		const char *key;
		const char *path;
	} test_cases[] = {
		{ "shared/./key", ".test-dict/.../key" },
		{ "shared/../key", ".test-dict/..../key" },
		{ "shared/.../key", ".test-dict/...../key" },
		{ "shared/..../key", ".test-dict/....../key" },
		{ "shared/...../key", ".test-dict/......./key" },
		{ "shared/key/.", ".test-dict/key/..." },
		{ "shared/key/..", ".test-dict/key/...." },
		{ "shared/key/...", ".test-dict/key/....." },
		{ "shared/key/....", ".test-dict/key/......" },
		{ "shared/key/.....", ".test-dict/key/......." },
		{ "shared/key/.key", ".test-dict/key/.key" },
		{ "shared/key/..key", ".test-dict/key/..key" },
		{ "shared/key/...key", ".test-dict/key/...key" },
		{ "shared/.key/key", ".test-dict/.key/key" },
		{ "shared/..key/key", ".test-dict/..key/key" },
		{ "shared/...key/key", ".test-dict/...key/key" },
	};
	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		test_dict_set_get(dict, test_cases[i].key, "1");
		test_assert(test_file_exists(test_cases[i].path));
	}

	/* per user paths */
	test_dict_set_get(dict, "priv/value", "priv1");
	test_assert(test_file_exists(".test-dict/testuser/value"));
	test_dict_set_get(dict, "priv/path/with/value", "priv2");
	test_assert(test_file_exists(".test-dict/testuser/path/with/value"));

	/* check that dots work correctly */
	test_dict_set_get(dict, "shared/../test-dict-fs.c", "3");
	test_assert(test_file_exists(".test-dict/..../test-dict-fs.c"));
	test_dict_set_get(dict, "shared/./test", "4");
	test_assert(test_file_exists(".test-dict/.../test"));
	test_dict_set_get(dict, "shared/.test", "5");
	test_assert(test_file_exists(".test-dict/.test"));
	test_dict_set_get(dict, "shared/..test", "6");
	test_assert(test_file_exists(".test-dict/..test"));
	dict_deinit(&dict);

	if (unlink_directory(".test-dict", UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0)
		i_fatal("unlink_directory(.test_dict) failed: %s", error);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dict_fs_set_get,
		NULL
	};
	int ret;
	dict_driver_register(&dict_driver_fs);
	ret = test_run(test_functions);
	dict_driver_unregister(&dict_driver_fs);
	return ret;
}
