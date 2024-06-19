/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-service.h"
#include "test-common.h"

static void test_version_is_valid(void)
{
	test_begin("version_is_valid");

	test_assert(version_is_valid("1"));
	test_assert(version_is_valid("1.0"));
	test_assert(version_is_valid("1.0.2"));
	test_assert(version_is_valid("999.88.77777.6666666.55"));

	test_assert(!version_is_valid(""));
	test_assert(!version_is_valid("."));
	test_assert(!version_is_valid("1."));
	test_assert(!version_is_valid(".1"));
	test_assert(!version_is_valid("1..0"));
	test_assert(!version_is_valid("1.0."));
	test_assert(!version_is_valid("1.0.."));
	test_assert(!version_is_valid("v"));
	test_assert(!version_is_valid("v1"));
	test_assert(!version_is_valid("1v"));
	test_assert(!version_is_valid("1.v"));
	test_assert(!version_is_valid("1.0v"));

	test_end();
}

static void test_version_cmp(void)
{
	static const struct {
		const char *v1, *v2;
		int ret;
	} tests[] = {
		{ "1", "1", 0 },
		{ "1.2.3", "1.2.3", 0 },
		{ "1", "2", -1 },
		{ "1.1", "2", -1 },
		{ "1.1", "1", 1 },
		{ "1.1", "1.0", 1 },
		{ "1.1", "1.0.0", 1 },
		{ "1.1", "1.0.9", 1 },
		{ "3.0.0", "3.0.9.4", -1 },
		{ "3.1.0", "3.0.9.4", 1 },
		{ NULL, NULL, 0 },
	};

	test_begin("version_cmp");
	for (unsigned int i = 0; tests[i].v1 != NULL; i++) {
		test_assert_idx(version_cmp(tests[i].v1, tests[i].v2) == tests[i].ret, i);
		test_assert_idx(version_cmp(tests[i].v2, tests[i].v1) == -tests[i].ret, i);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_version_is_valid,
		test_version_cmp,
		NULL
	};
	return test_run(test_functions);
}
