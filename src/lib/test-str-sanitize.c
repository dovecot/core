/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "str-sanitize.h"

struct str_sanitize_test {
	const char *str;
	unsigned int max_len;
	const char *sanitized; /* NULL for no change */
};

static void test_str_sanitize_max_bytes(void)
{
	static const struct str_sanitize_test tests[] = {
		{ NULL,    2, NULL },
		{ "",      2, NULL },
		{ "a",     2, NULL },
		{ "ab",    2, NULL },
		{ "abc",   2, "..." },
		{ "abcd",  3, "..." },
		{ "abcde", 4, "a..." },
		{ "\xD1\x81",     1, "..." },
		{ "\xD1\x81",     2, "\xD1\x81" },
		{ "\xD1\x81",     3, NULL },
		{ "\xC3\xA4\xC3\xA4zyxa", 1, "..." },
		{ "\xC3\xA4\xC3\xA4zyxa", 2, "..." },
		{ "\xC3\xA4\xC3\xA4zyxa", 3, "..." },
		{ "\xC3\xA4\xC3\xA4zyxa", 4, "..." },
		{ "\xC3\xA4\xC3\xA4zyxa", 5, "\xC3\xA4..." },
		{ "\xC3\xA4\xC3\xA4zyxa", 6, "\xC3\xA4..." },
		{ "\xC3\xA4\xC3\xA4zyxa", 7, "\xC3\xA4\xC3\xA4..." },
		{ "\xC3\xA4\xC3\xA4zyxa", 8, "\xC3\xA4\xC3\xA4zyxa" },
		{ "\001x\x1fy\x81", 10, "?x?y?" }
	};
	const char *str;
	string_t *str2;
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

	test_begin("str_sanitize_append");
	str2 = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		if (tests[i].str == NULL)
			continue;
		str_truncate(str2, 0);
		str_append(str2, "1234567890");
		str_sanitize_append(str2, tests[i].str, tests[i].max_len);

		test_assert_idx(str_begins(str_c(str2), "1234567890"), i);
		if (tests[i].sanitized != NULL)
			test_assert_idx(strcmp(str_c(str2)+10, tests[i].sanitized) == 0, i);
		else
			test_assert_idx(strcmp(str_c(str2)+10, tests[i].str) == 0, i);
	}
	test_end();
}

static void test_str_sanitize_max_codepoints(void)
{
	static const struct str_sanitize_test tests[] = {
		{ NULL,    2, NULL },
		{ "",      2, NULL },
		{ "a",     2, NULL },
		{ "ab",    2, NULL },
		{ "abc",   2, "a\xE2\x80\xA6" },
		{ "abcd",  3, "ab\xE2\x80\xA6" },
		{ "abcde", 4, "abc\xE2\x80\xA6" },
		{ "\xD1\x81",     1, "\xD1\x81" },
		{ "\xD1\x81",     2, "\xD1\x81" },
		{ "\xD1\x81",     3, NULL },
		{ "\xC3\xA4\xC3\xA4zyxa", 1, "\xE2\x80\xA6" },
		{ "\xC3\xA4\xC3\xA4zyxa", 2, "\xC3\xA4\xE2\x80\xA6" },
		{ "\xC3\xA4\xC3\xA4zyxa", 3, "\xC3\xA4\xC3\xA4\xE2\x80\xA6" },
		{ "\xC3\xA4\xC3\xA4zyxa", 4, "\xC3\xA4\xC3\xA4z\xE2\x80\xA6" },
		{ "\xC3\xA4\xC3\xA4zyxa", 5, "\xC3\xA4\xC3\xA4zy\xE2\x80\xA6" },
		{ "\xC3\xA4\xC3\xA4zyxa", 6, "\xC3\xA4\xC3\xA4zyxa" },
		{ "\xC3\xA4\xC3\xA4zyxa", 7, "\xC3\xA4\xC3\xA4zyxa" },
		{ "\xC3\xA4\xC3\xA4zyxa", 8, "\xC3\xA4\xC3\xA4zyxa" },
		{ "\001x\x1fy\x81", 10, "\xEF\xBF\xBDx\xEF\xBF\xBDy\xEF\xBF\xBD" }
	};
	const char *str;
	string_t *str2;
	unsigned int i;

	test_begin("str_sanitize_utf8");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str = str_sanitize_utf8(tests[i].str, tests[i].max_len);
		if (tests[i].sanitized != NULL)
			test_assert_idx(null_strcmp(str, tests[i].sanitized) == 0, i);
		else
			test_assert_idx(str == tests[i].str, i);
	}
	test_end();

	test_begin("str_sanitize_append_utf8");
	str2 = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		if (tests[i].str == NULL)
			continue;
		str_truncate(str2, 0);
		str_append(str2, "1234567890");
		str_sanitize_append_utf8(str2, tests[i].str, tests[i].max_len);

		test_assert_idx(strncmp(str_c(str2), "1234567890", 10) == 0, i);
		if (tests[i].sanitized != NULL)
			test_assert_idx(strcmp(str_c(str2)+10, tests[i].sanitized) == 0, i);
		else
			test_assert_idx(strcmp(str_c(str2)+10, tests[i].str) == 0, i);
	}
	test_end();
}

void test_str_sanitize(void)
{
	test_str_sanitize_max_bytes();
	test_str_sanitize_max_codepoints();
}
