/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "test-common.h"

#define VERBOSE FALSE

#if VERBOSE
#	include <stdio.h>
#endif

static void run_test(const char *title,
		     const unsigned char *input, size_t size,
		     const char *output[])
{
	struct rfc822_parser_context parser;
	const char *const *result;
	unsigned int i;

	test_begin(title);
	rfc822_parser_init(&parser, input, size, NULL);
	test_assert(rfc2231_parse(&parser, &result) == 0);
	for (i = 0; output[i] != NULL && result[i] != NULL; i++) {
		#if VERBOSE
			printf("output[%d] = %s\n", i, output[i]);
			printf("result[%d] = %s\n", i, result[i]);
		#endif
		test_assert_idx(strcmp(output[i], result[i]) == 0, i);
	}
	rfc822_parser_deinit(&parser);
	test_assert(output[i] == NULL && result[i] == NULL);
	test_end();
}

static void test_rfc2231_parser_rfc_tests_1(void)
{
	const unsigned char input[] =
		"; title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A";
	const char *output[] = {
		"title",
		"This is ***fun***",
		NULL
	};
	run_test("rfc2231 RFC document tests 1", input, sizeof(input)-1, output);
}

static void test_rfc2231_parser_rfc_tests_2(void)
{
	const unsigned char input[] =
		"; title*0*=us-ascii'en'This%20is%20even%20more%20"
		"; title*1*=%2A%2A%2Afun%2A%2A%2A%20"
		"; title*2=\"isn't it!\"";
	const char *output[] = {
		"title",
		"This is even more ***fun*** isn't it!",
		NULL
	};
	run_test("rfc2231 RFC document tests 2", input, sizeof(input)-1, output);
}

static void test_rfc2231_spaces(void)
{
	const unsigned char input[] =
		"; title*=us-ascii'en-us'%20%20%20";
	const char *output[] = {
		"title",
		"   ",
		NULL
	};
	run_test("rfc2231 RFC document tests 1", input, sizeof(input)-1, output);
}

static void test_rfc2231_parser(void)
{
	const unsigned char input[] =
		"; key4*=us-ascii''foo"
		"; key*2=ba%"
		"; key2*0*=us-ascii''a"
		"; key3*0*=us-ascii'en'xyz"
		"; key*0=\"f\0oo\""
		"; key2*1*=b%25"
		"; key3*1=plop%"
		"; key*1=baz";
	const char *output[] = {
		"key4",
		"foo",
		"key",
		"f\xEF\xBF\xBDoobazba%",
		"key2",
		"ab%",
		"key3",
		"xyzplop%",
		NULL
	};
	run_test("rfc2231 parser", input, sizeof(input)-1, output);
}

static void test_rfc2231_parser_redundant_keys(void)
{
	const unsigned char input[] =
		"; key3=foobar"
		"; key3*=us-ascii''foo";
	const char *output[] = {
		"key3",
		"foobar",
		NULL
	};
	run_test("rfc2231 parser redundant keys", input, sizeof(input)-1, output);
}

static void test_rfc2231_parser_redundant_single_and_multisegment_keys(void)
{
	const unsigned char input[] =
		"; key2*0*=us-ascii''foo"
		"; key2*1*=baz"
		"; key2=foobar";
	const char *output[] = {
		"key2",
		"foobar",
		NULL
	};
	run_test(
		"rfc2231 parser redundant single and multisegment keys",
		input, sizeof(input) - 1, output);
}

static void test_rfc2231_parser_redundant_extended_and_multisegment_keys(void)
{
	const unsigned char input[] =
		"; key1*0*=us-ascii''foo"
		"; key1*1*=baz"
		"; key1*=foobar";
	const char *output[] = {
		"key1",
		"foobar",
		NULL
	};
	run_test(
		"rfc2231 parser redundant extended and multisegment keys",
		input, sizeof(input)-1, output);
}

static void test_rfc2231_parser_redundant_multisegment_keys(void)
{
	const unsigned char input[] =
		"; key1*0*=us-ascii''foo"
		"; key1*1*=baz1"
		"; key1*0*=foobar"
		"; key1*1*=baz2"
		"; key1*=foobaz3";
	const char *output[] = {
		"key1",
		"foobaz3",
		"key1*0",
		"foo",
		"key1*1",
		"baz1",
		NULL
	};
	run_test("rfc2231 parser redundant multisegment keys",
		 input, sizeof(input)-1, output);
}

static void test_rfc2231_parser_invalid_sequence(void)
{
	const unsigned char input[] =
		"; key1*0*=us-ascii''foo"
		"; key1*2*=baz";
	const char *output[] = {
		"key1*0",
		"foo",
		"key1*2",
		"baz",
		NULL
	};
	run_test("rfc2231 parser invalid sequence", input, sizeof(input)-1, output);
}

static void test_rfc2231_parser_encodings(void)
{
	const unsigned char input[] =
		"; key1*=iso-8859-1''foo%E5%E4"
		"; key2*=us-ascii''foo%E5%E4"
		"; key3*=us-ascii''foo%00"
		"; key4*=us-ascii''foo%ff%ff"
		"; key5*=''foo%C3%A5%C3%A4"
		"; key6*=us-ascii''foo%C3%A5%C3%A4"
		"; key7*=us-ascii''foo%80";
	const char *output[] = {
		"key1",
		"fooåä",
		"key2",
		"foo%E5%E4",
		"key3",
		"foo\0",
		"key4",
		"foo%ff%ff",
		"key5",
		"foo%C3%A5%C3%A4",
		"key6",
		"fooåä",
		"key7",
		"foo%80",
		NULL
	};
	run_test("rfc2231 parser invalid encoding", input, sizeof(input)-1, output);
}

static void test_rfc2231_parser_utf8_encoding(void)
{
	const unsigned char input[] =
		"; key1*=utf-8''foo%E5%E4"
		"; key2*=utf-8''foo%00"
		"; key3*=utf-8''foo%ff%ff"
		"; key4*=utf-8''foo%C3%A5%C3%A4"
		"; key5*=utf-8''foo%80";
	const char *output[] = {
		"key1",
		"foo%E5%E4",
		"key2",
		"foo\0",
		"key3",
		"foo%ff%ff",
		"key4",
		"fooåä",
		"key5",
		"foo%80",
		NULL
	};
	run_test("rfc2231 parser invalid encoding", input, sizeof(input)-1, output);
}

static void test_rfc2231_parser_multi_encodings(void)
{
	const unsigned char input[] =
		"; key1*0*=iso-8859-1''foo%E5%E4-"
		"; key1*1*=utf-8''foo%E5%E4"
		"; key2*0*=utf-8''foo%C3%A5%C3%A4-"
		"; key2*1*=iso-8859-1''foo%E5%E4";
	const char *output[] = {
		"key1",
		"fooåä-utf-8''fooåä",
		"key2",
		"fooåä-iso-8859-1''foo%E5%E4",
		NULL
	};
	run_test("rfc2231 parser invalid encoding", input, sizeof(input)-1, output);
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_rfc2231_parser_rfc_tests_1,
		test_rfc2231_parser_rfc_tests_2,
		test_rfc2231_spaces,
		test_rfc2231_parser,
		test_rfc2231_parser_redundant_keys,
		test_rfc2231_parser_redundant_single_and_multisegment_keys,
		test_rfc2231_parser_redundant_extended_and_multisegment_keys,
		test_rfc2231_parser_redundant_multisegment_keys,
		test_rfc2231_parser_invalid_sequence,
		test_rfc2231_parser_encodings,
		test_rfc2231_parser_utf8_encoding,
		test_rfc2231_parser_multi_encodings,
		NULL
	};
	return test_run(test_functions);
}
