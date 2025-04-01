/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "strnum.h"
#include "str.h"
#include "unichar.h"

static const struct casemap_test {
	const char *input;
	const char *lowercase;
	const char *uppercase;
	const char *casefold;
} tests[] = {
	{
		/* Wei<U+00DF>kopfseeadler */
		.input = "\x57\x65\x69\xC3\x9F\x6B\x6F\x70\x66"
			 "\x73\x65\x65\x61\x64\x6C\x65\x72",
		/* WEISSKOPFSEEADLER */
		.uppercase = "WEISSKOPFSEEADLER",
		/* wei<U+00DF>kopfseeadler */
		.lowercase = "\x77\x65\x69\xC3\x9F\x6B\x6F\x70"
			     "\x66\x73\x65\x65\x61\x64\x6C\x65\x72",
		/* weisskopfseeadler */
		.casefold = "weisskopfseeadler",
	},
	{
		/* aBcD<U+00C4><U+00E4> */
		.input = "aBcD\xC3\x84\xC3\xA4",
		/* ABCD<U+00C4><U+00C4> */
		.uppercase = "ABCD\xC3\x84\xC3\x84",
		/* abcd<U+00E4><U+00E4> */
		.lowercase = "abcd\xC3\xA4\xC3\xA4",
	}
};

static const unsigned int tests_count = N_ELEMENTS(tests);

void test_unicode_casemap(void)
{
	unsigned int i;

	test_begin("unicode casemap");

	for (i = 0; i < tests_count; i++) {
		const struct casemap_test *test = &tests[i];
		const char *uppercase, *lowercase, *casefold;
		const char *test_casefold =
			(test->casefold != NULL ?
			 test->casefold : test->lowercase);
		int ret;

		ret = uni_utf8_to_uppercase(test->input, strlen(test->input),
					    &uppercase);
		test_assert_idx(ret >= 0, i);
		test_assert_strcmp_idx(test->uppercase, uppercase, i);

		ret = uni_utf8_to_lowercase(test->input, strlen(test->input),
					    &lowercase);
		test_assert_idx(ret >= 0, i);
		test_assert_strcmp_idx(test->lowercase, lowercase, i);

		ret = uni_utf8_to_casefold(test->input, strlen(test->input),
					   &casefold);
		test_assert_idx(ret >= 0, i);
		test_assert_strcmp_idx(test_casefold, casefold, i);
	}

	test_end();
}
