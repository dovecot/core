/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "message-parser.h"
#include "message-part.h"
#include "message-part-serialize.h"
#include "test-common.h"

static const struct message_parser_settings set_empty = { .flags = 0 };

static int message_parse_stream(pool_t pool, struct istream *input,
				const struct message_parser_settings *set,
				struct message_part **parts_r)
{
	int ret;
	struct message_parser_ctx *parser;
	struct message_block block;

	i_zero(&block);
	parser = message_parser_init(pool, input, set);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	message_parser_deinit(&parser, parts_r);
	test_assert(input->stream_errno == 0);
	return ret;
}

static void test_parsed_parts(struct istream *input, struct message_part *parts)
{
	const struct message_parser_settings parser_set = {
		.flags = MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK,
	};
	struct message_parser_ctx *parser;
	struct message_block block;
	struct message_part *parts2;
	const char *error;

	i_stream_seek(input, 0);

	parser = message_parser_init_from_parts(parts, input, &parser_set);
	while (message_parser_parse_next_block(parser, &block) > 0) ;
	test_assert(message_parser_deinit_from_parts(&parser, &parts2, &error) == 0);
	test_assert(message_part_is_equal(parts, parts2));
}

#define TEST_CASE_DATA(x) \
	{ .value = (const unsigned char*)((x)), .value_len = sizeof((x))-1 }

static void test_message_serialize_deserialize(void)
{
static struct test_case {
	struct test_case_data {
		const unsigned char *value;
		size_t value_len;
	} input;
	int expect_ret;
} test_cases[] = {
	{
		.input = TEST_CASE_DATA("hello, world"),
		.expect_ret = -1,
	},
	{
		.input = TEST_CASE_DATA(
"Subject: Hide and seek\n"
"MIME-Version: 1.0\n"
"Content-Type: multipart/mixed; boundary=1\n"
"\n--1\n"
"Content-Type: multipart/signed; protocol=\"signature/plain\"; migalc=\"pen+paper\"; boundary=2\n"
"X-Signature-Type: penmanship\n"
"\n--2\n"
"Content-Type: multipart/alternative; boundary=3\n"
"\n--3\n"
"Content-Type: text/html; charset=us-ascii\n\n"
"<html><head><title>Search me</title></head><body><p>Don't find me here</p></body></html>\n"
"\n--3\n"
"Content-Type: text/plain\n"
"Content-Transfer-Encoding: binary\n"
"\n"
"Search me, and Find me here"
"\n--3--\n"
"\n--2\n"
"Content-Type: signature/plain; charset=us-ascii\n"
"\n"
"Signed by undersigned"
"\n--2--\n"
"\n--1--"),
		.expect_ret = -1,
	},
	{
		.input = TEST_CASE_DATA(
"From: Moderator-Address <moderator>\n" \
"Content-Type: multipart/digest; boundary=1;\n" \
"\n\n--1\n" \
"From: someone-else <someone@else>\n" \
"Subject: my opinion\n" \
"\n" \
"This is my opinion" \
"\n--1\n\n" \
"From: another one <another@one>\n" \
"Subject: i disagree\n" \
"\n" \
"Not agreeing one bit!" \
"\n--1\n\n" \
"From: attachment <attachment@user>\n" \
"Subject: funny hat\n" \
"Content-Type: multipart/mixed; boundary=2\n" \
"\n--2\n" \
"Content-Type: text/plain\n"
"Content-Transfer-Encoding: binary\n"
"\n" \
"Lovely attachment for you" \
"\n--2\n" \
"Content-Type: application/octet-stream; disposition=attachment; name=\"test.txt\"\n" \
"Content-Transfer-Encoding: binary\n" \
"\n" \
"Foobar" \
"\n--2--" \
"\n--1--"),
		.expect_ret = -1,
	},
};
	test_begin("message part serialize deserialize");
	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		const struct test_case *tc = &test_cases[i];
		struct message_part *parts;
		const char *error;
		pool_t pool = pool_alloconly_create("message parser", 10240);
		struct istream *is =
			test_istream_create_data(tc->input.value, tc->input.value_len);
		test_assert(message_parse_stream(pool, is, &set_empty, &parts) ==
			    tc->expect_ret);
		buffer_t *dest = buffer_create_dynamic(pool, 256);
		message_part_serialize(parts, dest);
		parts = message_part_deserialize(pool, dest->data, dest->used,
						 &error);
		test_assert(parts != NULL);
		if (parts != NULL)
			test_parsed_parts(is, parts);
		else
			i_error("message_part_deserialize: %s", error);
		i_stream_unref(&is);
		pool_unref(&pool);
	}
	test_end();
}

#define TEST_CASE(data, size, expect_error) \
	test_assert(message_part_deserialize(pool, (data), (size), &error) == NULL); \
	test_assert_strcmp(error, (expect_error))

static void test_message_deserialize_errors(void)
{
	test_begin("message part deserialize errors");
	const char *error = NULL;
	struct message_part part, child1, child2;
	pool_t pool = pool_datastack_create();
	buffer_t *dest = buffer_create_dynamic(pool, 256);

	/* empty part */
	TEST_CASE("", 0, "Not enough data");

	/* truncated part */
	TEST_CASE("\x08\x00\x00", 3, "Not enough data");

	/* bad sizes */
	i_zero(&part);
	part.flags = MESSAGE_PART_FLAG_TEXT;
	part.header_size.virtual_size = 0;
	part.header_size.physical_size = 100;
	message_part_serialize(&part, dest);
	TEST_CASE(dest->data, dest->used, "header_size.virtual_size too small");
	buffer_set_used_size(dest, 0);

	i_zero(&part);
	part.flags = MESSAGE_PART_FLAG_TEXT;
	part.body_size.virtual_size = 0;
	part.body_size.physical_size = 100;
	message_part_serialize(&part, dest);
	TEST_CASE(dest->data, dest->used, "body_size.virtual_size too small");
	buffer_set_used_size(dest, 0);

	i_zero(&part);
	part.flags = MESSAGE_PART_FLAG_MESSAGE_RFC822;
	message_part_serialize(&part, dest);
	TEST_CASE(dest->data, dest->used, "message/rfc822 part has no children");
	buffer_set_used_size(dest, 0);

	i_zero(&part);
	i_zero(&child1);
	i_zero(&child2);
	part.flags = MESSAGE_PART_FLAG_MESSAGE_RFC822;
	part.children_count = 2;
	child1.flags = MESSAGE_PART_FLAG_TEXT;
	child1.parent = &part;
	part.children = &child1;
	child2.flags = MESSAGE_PART_FLAG_TEXT;
	part.children->next = &child2;
	child2.parent = &part;
	message_part_serialize(&part, dest);
	TEST_CASE(dest->data, dest->used, "message/rfc822 part has multiple children");
	buffer_set_used_size(dest, 0);

	i_zero(&part);
	i_zero(&child1);
	part.flags = MESSAGE_PART_FLAG_MULTIPART|MESSAGE_PART_FLAG_IS_MIME;
	part.children_count = 1;
	child1.flags = MESSAGE_PART_FLAG_TEXT;
	child1.parent = &part;
	part.children = &child1;
	message_part_serialize(&part, dest);
	for (size_t i = 0; i < dest->used - 1; i++)
		TEST_CASE(dest->data, i, "Not enough data");
	buffer_append_c(dest, '\x00');
	TEST_CASE(dest->data, dest->used, "Too much data");

	test_end();
}

static enum fatal_test_state test_message_deserialize_fatals(unsigned int stage)
{
	const char *error = NULL;
	struct message_part part, child1, child2;

	pool_t pool = pool_datastack_create();
	buffer_t *dest = buffer_create_dynamic(pool, 256);

	switch(stage) {
	case 0:
		test_expect_fatal_string("part->children == NULL");
		test_begin("message deserialize fatals");
		i_zero(&part);
		i_zero(&child1);
		i_zero(&child2);
		part.flags = MESSAGE_PART_FLAG_MULTIPART|MESSAGE_PART_FLAG_IS_MIME;
		part.children_count = 1;
		child1.flags = MESSAGE_PART_FLAG_TEXT;
		child1.parent = &part;
		part.children = &child1;
		child2.parent = &child1;
		child1.children_count = 1;
		child1.children = &child2;

		message_part_serialize(&part, dest);
		TEST_CASE(dest->data, dest->used, "message/rfc822 part has multiple children");
		buffer_set_used_size(dest, 0);
		return FATAL_TEST_FAILURE;
	};

	test_end();
	return FATAL_TEST_FINISHED;
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_serialize_deserialize,
		test_message_deserialize_errors,
		NULL
	};
	static enum fatal_test_state (*const fatal_functions[])(unsigned int) = {
		test_message_deserialize_fatals,
		NULL
	};
	return test_run_with_fatals(test_functions, fatal_functions);
}
