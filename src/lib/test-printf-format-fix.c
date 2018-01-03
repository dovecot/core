/* Copyright (c) 2001-2018 Dovecot authors, see the included COPYING file */

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
		"Embedded %%, %u, %f, %s, etc. are OK",
		"Allow %#0- +s flags",
		"duplicate flags in different args %0-123s %0-123s",
		"Minimum length %9999s",
		"Minimum length parameter %*s",
		"Precision %.9999s",
		"Precision %1.9999s",
		"Precision parameter %1.*s %.*s",
		"Floating precisions such as %.0f %0.4f %-4.0f",
		"Length modifiers %hd %hhd %ld %lld %Lg %jd %zd %td",
		"Specifiers %s %u %d %c %i %x %X %p %o %e %E %f %F %g %G %a %A",
		"%%doesn't cause confusion in %%m and %%n",
	};
	unsigned int i;

	test_begin("printf_format_fix(safe)");
	for (i = 0; i < N_ELEMENTS(tests); ++i) {
		size_t len;
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
	i_assert(needle != NULL);
	needlen = strlen(needle);

	for (i = 0; i < N_ELEMENTS(tests); ++i) {
		size_t len;
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
}

/* Want to test the panics too? go for it! */
enum fatal_test_state fatal_printf_format_fix(unsigned int stage)
{
	static const struct {
		const char *format;
		const char *expected_fatal;
	} fatals[] = {
		{ "no no no %n's", "%n modifier used" },
		{ "no no no %-1234567890123n's with extra stuff", "Too large minimum field width" },
		{ "%m allowed once, but not twice: %m", "%m used twice" },
		{ "%m must not obscure a later %n", "%n modifier used" },
		{ "definitely can't have a tailing %", "Missing % specifier" },
		{ "Evil %**%n", "Unsupported 0x2a specifier" },
		{ "Evil %*#%99999$s", "Unsupported 0x23 specifier" },
		{ "No weird %% with %0%", "Unsupported 0x25 specifier" },
		{ "No duplicate modifiers %00s", "Duplicate % flag '0'" },
		{ "Minimum length can't be too long %10000s", "Too large minimum field width" },
		{ "Minimum length doesn't support %*1$s", "Unsupported 0x31 specifier" },
		{ "Precision can't be too long %.10000s", "Too large precision" },
		{ "Precision can't be too long %1.10000s", "Too large precision" },
		{ "Precision doesn't support %1.-1s", "Unsupported 0x2d specifier" },
	};

	if(stage >= N_ELEMENTS(fatals)) {
		test_end();
		return FATAL_TEST_FINISHED;
	}

	if(stage == 0)
		test_begin("fatal_printf_format_fix");

	/* let's crash! */
	test_expect_fatal_string(fatals[stage].expected_fatal);
	(void)printf_format_fix(fatals[stage].format);
	return FATAL_TEST_FAILURE;
}
