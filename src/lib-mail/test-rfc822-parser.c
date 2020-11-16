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
	parser.nul_replacement_str = "!";
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

static void test_rfc822_parse_dot_atom(void)
{
	static const struct {
		const char *input, *output;
		int ret;
	} tests[] = {
		{ "foo", "foo", 0 },
		{ "foo.bar", "foo.bar", 0 },
		{ "foo.bar.baz", "foo.bar.baz", 0 },
		{ "foo  . \tbar (comments) . (...) baz\t  ", "foo.bar.baz", 0 },

		{ ".", "", -1 },
		{ "..", "", -1 },
		{ ".foo", "", -1 },
		{ "foo.", "foo.", -1 },
		{ "foo..bar", "foo.", -1 },
		{ "foo. .bar", "foo.", -1 },
		{ "foo.(middle).bar", "foo.", -1 },
		{ "foo. ", "foo.", -1 },
		{ "foo.\t", "foo.", -1 },
		{ "foo.(ending)", "foo.", -1 },
	};
	struct rfc822_parser_context parser;
	string_t *str = t_str_new(64);
	string_t *input2 = t_str_new(64);
	unsigned int i = 0;

	test_begin("rfc822 parse dot-atom");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		rfc822_parser_init(&parser, (const void *)tests[i].input,
				   strlen(tests[i].input), NULL);
		test_assert_idx(rfc822_parse_dot_atom(&parser, str) == tests[i].ret, i);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		rfc822_parser_deinit(&parser);
		str_truncate(str, 0);

		/* same input but with "," appended should return 1 on success,
		   and -1 still on error. */
		int expected_ret = tests[i].ret == -1 ? -1 : 1;
		str_append(input2, tests[i].input);
		str_append_c(input2, ',');
		rfc822_parser_init(&parser, str_data(input2),
				   str_len(input2), NULL);
		test_assert_idx(rfc822_parse_dot_atom(&parser, str) == expected_ret, i);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		rfc822_parser_deinit(&parser);

		str_truncate(str, 0);
		str_truncate(input2, 0);
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

#undef TEST_STRING
#define TEST_STRING(a) .input = (const unsigned char*)a, .input_len = sizeof(a)-1

static void test_rfc822_parse_content_type(void)
{
	const struct {
		const unsigned char *input;
		size_t input_len;
		int ret;
		const char *output;
	} test_cases[] = {
		{ TEST_STRING(""), -1, "" },
		{ TEST_STRING(";charset=us-ascii"), -1, "" },
		{ TEST_STRING(" ;charset=us-ascii"), -1, "" },
		{ TEST_STRING("/"), -1, "" },
		{ TEST_STRING("/;charset=us-ascii"), -1, "" },
		{ TEST_STRING("/ ;charset=us-ascii"), -1, "" },
		{ TEST_STRING("text/"), -1, "" },
		{ TEST_STRING("text/;charset=us-ascii"), -1, "" },
		{ TEST_STRING("text/ ;charset=us-ascii"), -1, "" },
		{ TEST_STRING("/plain"), -1, "" },
		{ TEST_STRING("/plain;charset=us-ascii"), -1, "" },
		{ TEST_STRING("/plain ;charset=us-ascii"), -1, "" },
		{ TEST_STRING("text/plain"), 0, "text/plain" },
		{ TEST_STRING("text/plain;charset=us-ascii"), 1, "text/plain" },
		{ TEST_STRING("text/plain ;charset=us-ascii"), 1, "text/plain" },
		{ TEST_STRING("text/plain/format"), -1, "" },
		{ TEST_STRING("text/plain/format;charset=us-ascii"), -1, "" },
		{ TEST_STRING("text/plain/format ;charset=us-ascii"), -1, "" },
		{ TEST_STRING("\xe5\x90\xab\xe9\x87\x8f/\xe7\xa8\xae\xe9\xa1\x9e"),
		  0, "\xe5\x90\xab\xe9\x87\x8f/\xe7\xa8\xae\xe9\xa1\x9e" },
		{ TEST_STRING("\xe5\x90\xab\xe9\x87\x8f/\xe7\xa8\xae\xe9\xa1\x9e;charset=utf-8"),
		  1, "\xe5\x90\xab\xe9\x87\x8f/\xe7\xa8\xae\xe9\xa1\x9e" },
		{ TEST_STRING("\xe5\x90\xab\xe9\x87\x8f/\xe7\xa8\xae\xe9\xa1\x9e ;charset=utf-8"),
		  1, "\xe5\x90\xab\xe9\x87\x8f/\xe7\xa8\xae\xe9\xa1\x9e" },
		{ TEST_STRING("application/ld+json"), 0, "application/ld+json" },
		{ TEST_STRING("application/ld+json;charset=us-ascii"),
		  1, "application/ld+json" },
		{ TEST_STRING("application/ld+json ;charset=us-ascii"),
		  1, "application/ld+json" },
		{ TEST_STRING("application/x-magic-cap-package-1.0"),
		  0, "application/x-magic-cap-package-1.0" },
		{ TEST_STRING("application/x-magic-cap-package-1.0;charset=us-ascii"),
		  1, "application/x-magic-cap-package-1.0" },
		{ TEST_STRING("application/x-magic-cap-package-1.0 ;charset=us-ascii"),
		  1, "application/x-magic-cap-package-1.0" },
		{ TEST_STRING("application/pro_eng"), 0, "application/pro_eng" },
		{ TEST_STRING("application/pro_eng;charset=us-ascii"),
		  1, "application/pro_eng" },
		{ TEST_STRING("application/pro_eng ;charset=us-ascii"),
		  1, "application/pro_eng" },
		{ TEST_STRING("application/wordperfect6.1"),
		  0, "application/wordperfect6.1" },
		{ TEST_STRING("application/wordperfect6.1;charset=us-ascii"),
		  1, "application/wordperfect6.1" },
		{ TEST_STRING("application/wordperfect6.1 ;charset=us-ascii"),
		  1, "application/wordperfect6.1" },
		{ TEST_STRING("application/vnd.openxmlformats-officedocument.wordprocessingml.template"),
		  0, "application/vnd.openxmlformats-officedocument.wordprocessingml.template" },
		{ TEST_STRING("application/vnd.openxmlformats-officedocument.wordprocessingml.template;charset=us-ascii"),
		  1, "application/vnd.openxmlformats-officedocument.wordprocessingml.template" },
		{ TEST_STRING("application/vnd.openxmlformats-officedocument.wordprocessingml.template ;charset=us-asii"),
		  1, "application/vnd.openxmlformats-officedocument.wordprocessingml.template" },
		{ TEST_STRING("(hello) text (plain) / (world) plain (eod)"),
		  0, "text/plain" },
		{ TEST_STRING("(hello) text (plain) / (world) plain (eod);charset=us-ascii"),
		  1, "text/plain" },
		{ TEST_STRING("(hello) text (plain) / (world) plain (eod); charset=us-ascii"),
		  1, "text/plain" },
		{ TEST_STRING("message/rfc822\r\n"), 0, "message/rfc822" },
		{ TEST_STRING(" \t\r message/rfc822 \t\r\n"),
		  0, "message/rfc822" },
		{ TEST_STRING(" \t\r message/rfc822 \t ;charset=us-ascii\r\n"),
		  1, "message/rfc822" },
		{ TEST_STRING(" \t\r message/rfc822 \t ; charset=us-ascii\r\n"),
		  1, "message/rfc822" },
		{ TEST_STRING("test\0/ty\0pe"), -1, "" },
	};

	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) T_BEGIN {
		string_t *value = t_str_new(64);
		struct rfc822_parser_context parser;

		rfc822_parser_init(&parser, test_cases[i].input,
				   test_cases[i].input_len, NULL);
		test_assert_idx(rfc822_parse_content_type(&parser, value) ==
				test_cases[i].ret, i);
		test_assert_strcmp_idx(test_cases[i].output, str_c(value), i);
		rfc822_parser_deinit(&parser);
	} T_END;
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
		test_rfc822_parse_dot_atom,
		test_rfc822_parse_domain_literal,
		test_rfc822_parse_content_type,
		test_rfc822_parse_content_param,
		NULL
	};
	return test_run(test_functions);
}
