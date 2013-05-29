/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-quote.h"
#include "test-common.h"

static void test_imap_append_string_for_humans(void)
{
	static struct {
		const char *input, *output;
	} tests[] = {
		{ "", "\"\"" },
		{ " ", "\"\"" },
		{ "  ", "\"\"" },
		{ "\t", "\"\"" },
		{ " \t", "\"\"" },
		{ " \t ", "\"\"" },
		{ " foo", "{3}\r\nfoo" },
		{ "\tfoo", "{3}\r\nfoo" },
		{ "\t \tfoo", "{3}\r\nfoo" },
		{ " foo ", "{3}\r\nfoo" },
		{ " foo  ", "{3}\r\nfoo" },
		{ " foo  \t  \t", "{3}\r\nfoo" }
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	test_begin("imap_append_string_for_humans()");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		imap_append_string_for_humans(str, (const void *)tests[i].input,
					      strlen(tests[i].input));
		test_assert(strcmp(tests[i].output, str_c(str)) == 0);
	}
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_append_string_for_humans,
		NULL
	};
	return test_run(test_functions);
}
