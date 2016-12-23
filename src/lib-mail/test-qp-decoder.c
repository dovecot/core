/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "qp-decoder.h"
#include "test-common.h"

struct test_quoted_printable_decode_data {
	const char *input;
	const char *output;
	size_t error_pos;
	int ret;
};

static void test_qp_decoder(void)
{
#define WHITESPACE10 "   \t   \t \t"
#define WHITESPACE70 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10 WHITESPACE10
	static struct test_quoted_printable_decode_data tests[] = {
		{ "foo  \r\nbar=\n", "foo\r\nbar", 0, 0 },
		{ "foo\t=\nbar", "foo\tbar", 0, 0 },
		{ "foo = \n=01", "foo \001", 0, 0 },
		{ "foo =\t\r\nbar", "foo bar", 0, 0 },
		{ "foo =\r\n=01", "foo \001", 0, 0 },
		{ "foo  \nbar=\r\n", "foo\r\nbar", 0, 0 },
		{ "=0A=0D  ", "\n\r", 0, 0 },
		{ "foo_bar", "foo_bar", 0, 0 },
		{ "\n\n", "\r\n\r\n", 0, 0 },
		{ "\r\n\n\n\r\n", "\r\n\r\n\r\n\r\n", 0, 0 },

		{ "foo=", "foo=", 4, -1 },
		{ "foo= \t", "foo= \t", 6, -1 },
		{ "foo= \r", "foo= \r", 6, -1 },
		{ "foo= \r bar", "foo= \r bar", 6, -1 },
		{ "foo=A", "foo=A", 5, -1 },
		{ "foo=Ax", "foo=Ax", 5, -1 },
		{ "foo=Ax=xy", "foo=Ax=xy", 5, -1 },

		/* above 76 whitespaces is invalid and gets truncated
		   (at 77th whitespace because of the current implementation) */
		{ WHITESPACE70"      7\n", WHITESPACE70"      7\r\n", 0, 0 },
		{ WHITESPACE70"       8\n", WHITESPACE70"       8\r\n", 77, -1 },
		{ WHITESPACE70"        9\n", WHITESPACE70"       9\r\n", 78, -1 },
		{ WHITESPACE70"         0\n", WHITESPACE70"       0\r\n", 79, -1 }
	};
	string_t *str;
	unsigned int i, j;

	test_begin("qp-decoder");
	str = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const char *input = tests[i].input;
		struct qp_decoder *qp = qp_decoder_init(str);
		size_t error_pos;
		const char *error;
		int ret;

		/* try all at once */
		ret = qp_decoder_more(qp, (const void *)input, strlen(input),
				      &error_pos, &error);
		if (qp_decoder_finish(qp, &error) < 0 && ret == 0) {
			error_pos = strlen(input);
			ret = -1;
		}
		test_assert_idx(ret == tests[i].ret, i);
		test_assert_idx(ret == 0 || error_pos == tests[i].error_pos, i);
		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);

		/* try in small pieces */
		str_truncate(str, 0);
		ret = 0;
		for (j = 0; input[j] != '\0'; j++) {
			unsigned char c = input[j];
			if (qp_decoder_more(qp, &c, 1, &error_pos, &error) < 0)
				ret = -1;
		}
		if (qp_decoder_finish(qp, &error) < 0)
			ret = -1;
		test_assert_idx(ret == tests[i].ret, i);
		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);

		qp_decoder_deinit(&qp);
		str_truncate(str, 0);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_qp_decoder,
		NULL
	};
	return test_run(test_functions);
}
