/* Copyright (c) 2007-2014 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str-sanitize.h"

struct str_sanitize_test {
	const char *str;
	unsigned int max_len;
	const char *sanitized; /* NULL for no change */
};

void test_str_sanitize(void)
{
	static struct str_sanitize_test tests[] = {
		{ NULL,    2, NULL },
		{ "",      2, NULL },
		{ "a",     2, NULL },
		{ "ab",    2, NULL },
		{ "abc",   2, "..." },
		{ "abcd",  3, "..." },
		{ "abcde", 4, "a..." },
		{ "с",    10, NULL },
		{ "с",     1, NULL },
		{ "\001x\x1fy\x81", 10, "?x?y?" }
	};
	const char *str;
	unsigned int i;

	test_begin("str_sanitize");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str = str_sanitize(tests[i].str, tests[i].max_len);
		if (tests[i].sanitized != NULL)
			test_assert_idx(null_strcmp(str, tests[i].sanitized) == 0, i);
		else
			test_assert_idx(str == tests[i].str, i);
	}
	test_end();
}
