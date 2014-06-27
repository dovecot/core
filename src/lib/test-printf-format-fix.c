/* Copyright (c) 2001-2014 Dovecot authors, see the included COPYING file */

/* Unit tests for printf-format-fix helper */

#include "test-lib.h"
#include "printf-format-fix.h"

#include <string.h>

struct format_fix_rewrites {
	const char *input;
	const char *output;
	size_t      length;
};

static void test_unchanged()
{
	static const char *tests[] = {
		"Hello world",
		"Embedded %%, %u, %f, etc. are OK",
		"%%doesn't cause confusion in %%m and %%n",
	};
	unsigned int i;

	test_begin("printf_format_fix(safe)");
	for (i = 0; i < N_ELEMENTS(tests); ++i) {
		unsigned int len;
		T_BEGIN {
			test_assert_idx(printf_format_fix(tests[i])
					== tests[i], i);
			test_assert_idx(printf_format_fix_get_len(tests[i], &len)
					== tests[i], i);
			test_assert_idx(len == strlen(tests[i]), i);
		} T_END;
	}
	test_end();
}

static void test_ok_changes()
{
	static const char *tests[] = {
		"OK to have a trailing %m",
		"%m can appear at the start too",
		"Even %m in the middle with a confusing %%m elsewhere is OK",
	};
	unsigned int i;
	const char *needle;
	unsigned int needlen;
	int old_errno = errno;

	test_begin("printf_format_fix(rewrites)");

	errno = EINVAL;
	needle = strerror(errno);
	test_assert(needle != NULL);
	needlen = strlen(needle);

	for (i = 0; i < N_ELEMENTS(tests); ++i) {
		unsigned int len;
		char const *chgd;
		char const *insert;
		unsigned int offs;

		T_BEGIN {
			chgd = printf_format_fix(tests[i]);
			test_assert_idx(chgd != tests[i], i);
			insert = strstr(chgd, needle);
			test_assert_idx(insert != NULL, i);
			offs = insert - chgd;
			test_assert_idx(memcmp(chgd, tests[i], offs) == 0, i);
			test_assert_idx(memcmp(chgd+offs, needle, needlen) == 0, i);
			test_assert_idx(strcmp(chgd+offs+needlen, tests[i]+offs+2) == 0, i);

			chgd = printf_format_fix_get_len(tests[i], &len);
			test_assert_idx(chgd != tests[i], i);
			test_assert_idx(len == strlen(chgd), i);
			insert = strstr(chgd, needle);
			test_assert_idx(insert != NULL, i);
			offs = insert - chgd;
			test_assert_idx(memcmp(chgd, tests[i], offs) == 0, i);
			test_assert_idx(memcmp(chgd+offs, needle, needlen) == 0, i);
			test_assert_idx(memcmp(chgd+offs+needlen, tests[i]+offs+2, len-needlen-offs) == 0, i);
		} T_END;
	}

	errno = old_errno;

	test_end();
}

void test_printf_format_fix()
{
	test_unchanged();
	test_ok_changes();
	/* want to test the panics too */
}
