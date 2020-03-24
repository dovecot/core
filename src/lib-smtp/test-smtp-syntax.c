/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"
#include "test-common.h"
#include "smtp-syntax.h"

/*
 * Valid string parse tests
 */

struct valid_string_parse_test {
	const char *input, *parsed, *output;
};

static const struct valid_string_parse_test
valid_string_parse_tests[] = {
	{
		.input = "",
		.parsed = "",
	},
	{
		.input = "atom",
		.parsed = "atom",
	},
	{
		.input = "abcdefghijklmnopqrstuvwxyz"
			 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			 "0123456789!#$%&'*+-/=?^_`{|}~",
		.parsed = "abcdefghijklmnopqrstuvwxyz"
			  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			  "0123456789!#$%&'*+-/=?^_`{|}~",
	},
	{
		.input = "\"quoted-string\"",
		.parsed = "quoted-string",
		.output = "quoted-string",
	},
	{
		.input = "\"quoted \\\"string\\\"\"",
		.parsed = "quoted \"string\"",
	},
	{
		.input = "\"quoted \\\\string\\\\\"",
		.parsed = "quoted \\string\\",
	},
};

static const unsigned int valid_string_parse_test_count =
	N_ELEMENTS(valid_string_parse_tests);

static void test_smtp_string_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_string_parse_test_count; i++) T_BEGIN {
		const struct valid_string_parse_test *test =
			&valid_string_parse_tests[i];
		const char *parsed, *error = NULL;
		int ret;

		ret = smtp_string_parse(test->input, &parsed, &error);

		test_begin(t_strdup_printf("smtp string valid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")", test->input),
				ret >= 0, error);
		test_assert(ret != 0 || *test->input == '\0');

		if (!test_has_failed()) {
			string_t *encoded;
			const char *output;

			test_out(t_strdup_printf("parsed = \"%s\"", parsed),
				 null_strcmp(parsed, test->parsed) == 0);

			encoded = t_str_new(255);
			smtp_string_write(encoded, parsed);
			output = (test->output == NULL ?
				  test->input : test->output);
			test_out(t_strdup_printf("write() = \"%s\"",
						 str_c(encoded)),
				 strcmp(str_c(encoded), output) == 0);
		}
		test_end();
	} T_END;
}

/*
 * Invalid string parse tests
 */

struct invalid_string_parse_test {
	const char *input;
};

static const struct invalid_string_parse_test
invalid_string_parse_tests[] = {
	{
		.input = " ",
	},
	{
		.input = "\\",
	},
	{
		.input = "\"",
	},
	{
		.input = "\"aa",
	},
	{
		.input = "aa\"",
	},
};

static const unsigned int invalid_string_parse_test_count =
	N_ELEMENTS(invalid_string_parse_tests);

static void test_smtp_string_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_string_parse_test_count; i++) T_BEGIN {
		const struct invalid_string_parse_test *test =
			&invalid_string_parse_tests[i];
		const char *parsed, *error;
		int ret;

		ret = smtp_string_parse(test->input, &parsed, &error);

		test_begin(t_strdup_printf("smtp string invalid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")", test->input),
				ret < 0, error);
		test_end();
	} T_END;
}

/*
 * Tests
 */

int main(void)
{
	static void (*test_functions[])(void) = {
		test_smtp_string_parse_valid,
		test_smtp_string_parse_invalid,
		NULL
	};
	return test_run(test_functions);
}
