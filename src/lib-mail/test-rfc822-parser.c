/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "rfc822-parser.h"
#include "test-common.h"

static void test_rfc822_parse_comment(void)
{
	static const struct {
		const char *input, *output;
		int ret;
	} tests[] = {
		{ "(", "", -1 },
		{ "(()", "", -1 },

		{ "()", "", 0 },
		{ "(())", "()", 0 },
		{ "(foo ( bar ) baz)", "foo ( bar ) baz", 0 },
		{ "(foo\t\tbar)", "foo\t\tbar", 0 },
		{ "(foo\\(bar)", "foo(bar", 0 },
		{ "(foo\\\\bar)", "foo\\bar", 0 },
		{ "(foo\\\\\\\\)", "foo\\\\", 0 },
		{ "(foo\\)bar)", "foo)bar", 0 },
		{ "(foo\"flop\"\"bar)", "foo\"flop\"\"bar", 0 },

		{ "(foo\n bar)", "foo bar", 0 },
		{ "(foo\n\t\t bar)", "foo\t\t bar", 0 },
		{ "(foo\\\n bar)", "foo\\ bar", 0 },
		{ "(foo\\\r\n bar)", "foo\\ bar", 0 },
	};
	struct rfc822_parser_context parser, parser2;
	string_t *str = t_str_new(64);
	unsigned int i = 0;

	test_begin("rfc822 parse comment");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		rfc822_parser_init(&parser, (const void *)tests[i].input,
				   strlen(tests[i].input), str);
		rfc822_parser_init(&parser2, (const void *)tests[i].input,
				   strlen(tests[i].input), NULL);
		test_assert_idx(rfc822_skip_comment(&parser) == tests[i].ret, i);
		test_assert_idx(rfc822_skip_comment(&parser2) == tests[i].ret, i);
		test_assert_idx(tests[i].ret < 0 ||
				strcmp(tests[i].output, str_c(str)) == 0, i);
		rfc822_parser_deinit(&parser);
		rfc822_parser_deinit(&parser2);
		str_truncate(str, 0);
	}
	test_end();
}

static void test_rfc822_parse_comment_nuls(void)
{
	const unsigned char input[] = "(\000a\000\000b\\\000c(\000d)\000)";
	const char output[] = "!a!!b\\!c(!d)!";
	struct rfc822_parser_context parser;
	string_t *str = t_str_new(64);

	test_begin("rfc822 parse comment with NULs");

	rfc822_parser_init(&parser, input, sizeof(input)-1, str);
	test_assert(rfc822_skip_comment(&parser) == 0);
	/* should be same as input, except the outer () removed */
	test_assert(str_len(str) == sizeof(input)-1-2 &&
		    memcmp(input+1, str_data(str), str_len(str)) == 0);
	rfc822_parser_deinit(&parser);

	str_truncate(str, 0);
	rfc822_parser_init(&parser, input, sizeof(input)-1, str);
	parser.nul_replacement_char = '!';
	test_assert(rfc822_skip_comment(&parser) == 0);
	test_assert(strcmp(str_c(str), output) == 0);
	rfc822_parser_deinit(&parser);

	test_end();
}

static void test_rfc822_parse_quoted_string(void)
{
	static const struct {
		const char *input, *output;
		int ret;
	} tests[] = {
		{ "\"", "", -1 },
		{ "\"\"", "", 0 },
		{ "\"foo\"", "foo", 0 },
		{ "\"\"foo", "", 1 },
		{ "\"\"\"", "", 1 },
		{ "\"\\\"\"", "\"", 0 },
		{ "\"\\\\\"", "\\", 0 },
		{ "\"\\\\foo\\\\foo\\\\\"", "\\foo\\foo\\", 0 },
		{ "\"foo\n bar\"", "foo bar", 0 },
		{ "\"foo\n\t\t bar\"", "foo\t\t bar", 0 },
		{ "\"foo\\\n bar\"", "foo\\ bar", 0 },
		{ "\"foo\\\r\n bar\"", "foo\\ bar", 0 },
	};
	struct rfc822_parser_context parser;
	string_t *str = t_str_new(64);
	unsigned int i = 0;

	test_begin("rfc822 parse quoted string");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		rfc822_parser_init(&parser, (const void *)tests[i].input,
				   strlen(tests[i].input), NULL);
		test_assert_idx(rfc822_parse_quoted_string(&parser, str) == tests[i].ret, i);
		test_assert_idx(tests[i].ret < 0 ||
				strcmp(tests[i].output, str_c(str)) == 0, i);
		rfc822_parser_deinit(&parser);
		str_truncate(str, 0);
	}
	test_end();
}

static void test_rfc822_parse_domain_literal(void)
{
	static const struct {
		const char *input, *output;
		int ret;
	} tests[] = {
		{ "@[", "", -1 },
		{ "@[foo", "", -1 },
		{ "@[foo[]", "", -1 },
		{ "@[foo[]]", "", -1 },
		{ "@[]", "[]", 0 },
		{ "@[foo bar]", "[foo bar]", 0 },
		{ "@[foo\n bar]", "[foo bar]", 0 },
		{ "@[foo\n\t\t bar]", "[foo\t\t bar]", 0 },
		{ "@[foo\\\n bar]", "[foo\\ bar]", 0 },
	};
	struct rfc822_parser_context parser;
	string_t *str = t_str_new(64);
	unsigned int i = 0;

	test_begin("rfc822 parse domain literal");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		rfc822_parser_init(&parser, (const void *)tests[i].input,
				   strlen(tests[i].input), NULL);
		test_assert_idx(rfc822_parse_domain(&parser, str) == tests[i].ret, i);
		test_assert_idx(tests[i].ret < 0 ||
				strcmp(tests[i].output, str_c(str)) == 0, i);
		rfc822_parser_deinit(&parser);
		str_truncate(str, 0);
	}
	test_end();
}

static void test_rfc822_parse_content_param(void)
{
	const char *input =
		"; key1=value1#$!%&'*+-.^_`{|}~"
		"; key2=\" \\\"(),/:;<=>?@[\\\\]\"";
	const struct {
		const char *key, *value;
	} output[] = {
		{ "key1", "value1#$!%&'*+-.^_`{|}~" },
		{ "key2", " \"(),/:;<=>?@[\\]" }
	};
	struct rfc822_parser_context parser;
	const char *key;
	string_t *value = t_str_new(64);
	unsigned int i = 0;
	int ret;

	test_begin("rfc822 parse content param");
	rfc822_parser_init(&parser, (const void *)input, strlen(input), NULL);
	while ((ret = rfc822_parse_content_param(&parser, &key, value)) > 0 &&
	       i < N_ELEMENTS(output)) {
		test_assert_idx(strcmp(output[i].key, key) == 0, i);
		test_assert_idx(strcmp(output[i].value, str_c(value)) == 0, i);
		i++;
	}
	rfc822_parser_deinit(&parser);
	test_assert(ret == 0);
	test_assert(i == N_ELEMENTS(output));
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_rfc822_parse_comment,
		test_rfc822_parse_comment_nuls,
		test_rfc822_parse_quoted_string,
		test_rfc822_parse_domain_literal,
		test_rfc822_parse_content_param,
		NULL
	};
	return test_run(test_functions);
}
