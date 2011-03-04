/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str-sanitize.h"

struct str_sanitize_input {
	const char *str;
	unsigned int max_len;
};

void test_str_sanitize(void)
{
	static struct str_sanitize_input input[] = {
		{ NULL, 2 },
		{ "", 2 },
		{ "a", 2 },
		{ "ab", 2 },
		{ "abc", 2 },
		{ "abcd", 3 },
		{ "abcde", 4 },
		{ "с", 10 },
		{ "с", 1 },
		{ "\001x\x1fy\x81", 10 }
	};
	static const char *output[] = {
		NULL,
		"",
		"a",
		"ab",
		"...",
		"...",
		"a...",
		"с",
		"с",
		"?x?y?"
	};
	const char *str;
	unsigned int i;

	test_begin("str_sanitize");
	for (i = 0; i < N_ELEMENTS(input); i++) {
		str = str_sanitize(input[i].str, input[i].max_len);
		test_assert(null_strcmp(output[i], str) == 0);
	}
	test_end();
}
