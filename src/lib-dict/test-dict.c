/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dict-private.h"
#include "test-common.h"

struct dict dict_driver_client;
struct dict dict_driver_file;

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

int main(void)
{
	static void (*test_functions[])(void) = {
		test_dict_escape,
		NULL
	};
	return test_run(test_functions);
}
