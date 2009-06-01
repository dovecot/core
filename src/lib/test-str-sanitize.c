/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

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
		{ "abcde", 4 }
	};
	static const char *output[] = {
		NULL,
		"",
		"a",
		"ab",
		"...",
		"...",
		"a..."
	};
	const char *str;
	unsigned int i;
	bool success;

	for (i = 0; i < N_ELEMENTS(input); i++) {
		str = str_sanitize(input[i].str, input[i].max_len);
		success = null_strcmp(output[i], str) == 0;
		test_out(t_strdup_printf("str_sanitize(%d)", i), success);
	}
}
