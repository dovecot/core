/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dict_escape,
		test_dict_async_lookup,
		NULL
	};
	return test_run(test_functions);
}
