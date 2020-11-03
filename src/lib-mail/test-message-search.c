/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "unichar.h"
#include "message-parser.h"
#include "message-search.h"
#include "test-common.h"

struct test_case_data {
	const unsigned char *value;
	size_t value_len;
};

#define TEST_CASE_DATA(x) \
	{ .value = (const unsigned char*)((x)), .value_len = sizeof((x))-1 }
#define TEST_CASE_DATA_EMPTY \
	{ .value = NULL, .value_len = 0 }
#define TEST_CASE_PLAIN_PREAMBLE \
"Content-Type: text/plain\n" \
"Content-Transfer-Encoding: binary\n"

struct test_case {
	struct test_case_data input;
	const char *search;
	struct test_case_data output;
	bool expect_found;
	bool expect_body;
	bool expect_header;
	const char *hdr_name;
};

static void compare_search_result(const struct test_case *tc,
				  const struct message_block *block,
				  size_t i)
{
	if (block->hdr != NULL) {
		/* found header */
		test_assert_idx(tc->expect_header == TRUE, i);
		test_assert_strcmp_idx(tc->hdr_name, block->hdr->name, i);
		test_assert_idx(tc->output.value_len <= block->hdr->full_value_len &&
				memcmp(tc->output.value, block->hdr->full_value,
				       tc->output.value_len) == 0, i);
	} else if (block->data != NULL) {
		/* found body */
		test_assert_idx(tc->expect_body == TRUE, i);
		test_assert_idx(tc->output.value_len <= block->size &&
				memcmp(tc->output.value, block->data,
				       tc->output.value_len) == 0, i);
	} else {
		test_assert_idx(tc->expect_header == FALSE, i);
		test_assert_idx(tc->expect_body == FALSE, i);
	}
}

#define SIGNED_MIME_CORPUS \
"Subject: Hide and seek\n" \
"MIME-Version: 1.0\n" \
"Content-Type: multipart/mixed; boundary=1\n" \
"\n--1\n" \
"Content-Type: multipart/signed; protocol=\"signature/plain\"; migalc=\"pen+paper\"; boundary=2\n" \
"X-Signature-Type: penmanship\n" \
"\n--2\n" \
"Content-Type: multipart/alternative; boundary=3\n" \
"\n--3\n" \
"Content-Type: text/html; charset=us-ascii\n\n" \
"<html><head><title>Search me</title></head><body><p>Don't find me here</p></body></html>\n" \
"\n--3\n" \
TEST_CASE_PLAIN_PREAMBLE \
"\n" \
"Search me, and Find me here" \
"\n--3--\n" \
"\n--2\n" \
"Content-Type: signature/plain; charset=us-ascii\n" \
"\n" \
"Signed by undersigned" \
"\n--2--\n" \
"\n--1--"

#define PARTIAL_MESSAGE_CORPUS \
"X-Weird-Header-1: Bar\n" \
"X-Weird-Header-2: Hello\n" \
"Message-ID: <c6cceebc-1dcf-11eb-be8c-f7ca132cbfea@example.org>\n" \
"Content-Type: text/plain; charset=\"us-ascii\"\n" \
"Content-Transfer-Encoding: base64\n" \
"\n" \
"dGhpcyBpcyB0aGUgZmlyc3QgcGFydCBvZiB0aGUgbWVzc2FnZQo="

#define PARTIAL_MIME_CORPUS \
"Subject: In parts\n" \
"MIME-Version: 1.0\n" \
"Content-Type: multipart/mixed; boundary=1\n" \
"\n--1\n" \
TEST_CASE_PLAIN_PREAMBLE \
"\n" \
"Hi, this is the fancy thing I was talking about!" \
"\n--1\n" \
"Content-Type: Message/Partial; number=1; total=5; id=\"heks68ewe@example.org\"\n" \
"\n" \
PARTIAL_MESSAGE_CORPUS \
"\n--1--\n"

#define UT8_CORPUS_CONTENT \
"\xe4\xba\xba\xe6\xa8\xa9\xe3\x81\xae\xe7\x84\xa1\xe8\xa6\x96\xe5\x8f\x8a"

#define UTF8_CORPUS \
"Subject: =?UTF-8?B?44GT44KT44Gr44Gh44Gv?=\n" \
"MIME-Version: 1.0\n" \
"Content-Type: multipart/mixed; boundary=1;\n" \
"  comment=\"\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf\xe5\xa2\x83\xe7\x95\x8c\xe3" \
	    "\x81\xae\xe3\x81\x82\xe3\x82\x8b\xe3\x83\xa1\xe3\x83\x83\xe3\x82" \
	    "\xbb\xe3\x83\xbc\xe3\x82\xb8\xe3\x81\xa7\xe3\x81\x99\"\n" \
"\n--1\n" \
TEST_CASE_PLAIN_PREAMBLE \
"Content-Language: ja\n" \
"\n" \
UT8_CORPUS_CONTENT \
"\n--1--"

#define MULTIPART_DIGEST_CORPUS \
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
TEST_CASE_PLAIN_PREAMBLE \
"\n" \
"Lovely attachment for you" \
"\n--2\n" \
"Content-Type: application/octet-stream; disposition=attachment; name=\"test.txt\"\n" \
"Content-Transfer-Encoding: binary\n" \
"\n" \
"Foobar" \
"\n--2--" \
"\n--1--"

static void test_message_search(void)
{
	const struct test_case test_cases[] = {
	{	/* basic test */
		.input = TEST_CASE_DATA(
"MIME-Version: 1.0\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Hello, world"),
		.search = "Hello",
		.output = TEST_CASE_DATA("Hello, world"),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{	/* look for something that's not found */
		.input = TEST_CASE_DATA(
"MIME-Version: 1.0\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Hallo, world"),
		.search = "Hello",
		.output = TEST_CASE_DATA_EMPTY,
		.expect_found = FALSE,
	},
	{	/* header value search */
		.input = TEST_CASE_DATA(
"Subject: Hello, World\n"
"MIME-Version: 1.0\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Hallo, world"),
		.search = "Hello",
		.output = TEST_CASE_DATA("Hello, World"),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "Subject",
	},
	{	/* header value wrapped in base64 */
		.input = TEST_CASE_DATA(
"Subject: =?UTF-8?B?SGVsbG8sIFdvcmxk?=\n"
"MIME-Version: 1.0\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Hallo, world"),
		.search = "Hello",
		.output = TEST_CASE_DATA("Hello, World"),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "Subject",
	},
	{	/* hidden inside one multipart */
		.input = TEST_CASE_DATA(
"Subject: Hide and seek\n"
"MIME-Version: 1.0\n"
"CONTENT-TYPE: MULTIPART/MIXED; BOUNDARY=\"A\"\n\n"
"--A\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Hallo, world"
"\n--A\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Hullo, world"
"\n--A\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Hello, world"
"\n--A--\n"
),
		.search = "Hello",
		.output = TEST_CASE_DATA("Hello, world"),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{	/* same with emoji boundary */
		.input = TEST_CASE_DATA(
"Subject: Hide and seek\n"
"MIME-Version: 1.0\n"
"CONTENT-TYPE: MULTIPART/MIXED; BOUNDARY=\"\xF0\x9F\x98\x82\"; COMMENT=\"Boundary is U+1F602\"\n\n"
"--\xF0\x9F\x98\x82\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Face with Tears of Joy"
"\n--\xF0\x9F\x98\x82\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Emoji"
"\n--\xF0\x9F\x98\x82--\n"
),
		.search = "Emoji",
		.output = TEST_CASE_DATA("Emoji"),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{       /* Nested body search */
		.input = TEST_CASE_DATA(SIGNED_MIME_CORPUS),
		.search = "Find me here",
		.output = TEST_CASE_DATA("Search me, and Find me here"),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{       /* Nested body search (won't look into signature/plain) */
		.input = TEST_CASE_DATA(SIGNED_MIME_CORPUS),
		.search = "undersigned",
		.output = TEST_CASE_DATA_EMPTY,
		.expect_found = FALSE,
	},
	{       /* Nested mime part header search */
		.input = TEST_CASE_DATA(SIGNED_MIME_CORPUS),
		.search = "penmanship",
		.output = TEST_CASE_DATA("penmanship"),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "X-Signature-Type",
	},
	{       /* Nested mime part header parameter search */
		.input = TEST_CASE_DATA(SIGNED_MIME_CORPUS),
		.search = "pen+paper",
		.output = TEST_CASE_DATA("multipart/signed; protocol=\"signature/plain\"; migalc=\"pen+paper\"; boundary=2"),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "Content-Type",
	},
	{       /* Partial message - must not parse the content */
		.input = TEST_CASE_DATA(PARTIAL_MIME_CORPUS),
		.search = "Bar",
		.output = TEST_CASE_DATA(PARTIAL_MESSAGE_CORPUS),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{	/* Partial message - must not parse the content */
		.input = TEST_CASE_DATA(PARTIAL_MIME_CORPUS),
		.search = "fancy thing",
		.output = TEST_CASE_DATA("Hi, this is the fancy thing I was talking about!"),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{	/* UTF-8 searches */
		.input = TEST_CASE_DATA(UTF8_CORPUS),
		.search = "\xe4\xba\xba\xe6\xa8\xa9",
		.output = TEST_CASE_DATA(UT8_CORPUS_CONTENT),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{       /* UTF-8 search header */
		.input = TEST_CASE_DATA(UTF8_CORPUS),
		.search = "\xe3\x81\x93\xe3\x82\x93",
		.output = TEST_CASE_DATA("\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf"),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "Subject",
	},
	{       /* UTF-8 searches content-type parameter */
		.input = TEST_CASE_DATA(UTF8_CORPUS),
		.search = "\xe3\x81\xa7\xe3\x81\x99",
		.output = TEST_CASE_DATA(
"multipart/mixed; boundary=1;\n  comment=\"\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf"
"\xe5\xa2\x83\xe7\x95\x8c\xe3\x81\xae\xe3\x81\x82\xe3\x82\x8b\xe3\x83\xa1\xe3"
"\x83\x83\xe3\x82\xbb\xe3\x83\xbc\xe3\x82\xb8\xe3\x81\xa7\xe3\x81\x99\""),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "Content-Type",
	},
	{
		/* Invalid UTF-8 boundary (should not matter) */
		.input = TEST_CASE_DATA(
"Content-Type: multipart/mixed; boundary=\"\xff\xff\xff\xff\"\n"
"\n--\xff\xff\xff\xff\n"
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Can you find me?"
"\n--\xff\xff\xff\xff--"),
		.search = "Can you find me?",
		.output = TEST_CASE_DATA("Can you find me?"),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{
		/* Invalid UTF-8 in subject (should work) */
		.input = TEST_CASE_DATA(
"Subject: =?UTF-8?B?Um90dGVuIP////8gdGV4dA==?="
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Such horror"),
		.search = "Rotten",
		.output = TEST_CASE_DATA("Rotten "UNICODE_REPLACEMENT_CHAR_UTF8" text"),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "Subject",
	},
	{
		/* Invalid UTF-8 in body (should work) */
		.input = TEST_CASE_DATA(
"Subject: =?UTF-8?B?Um90dGVuIP////8gdGV4dA==?="
TEST_CASE_PLAIN_PREAMBLE
"\n"
"Such horror \xff\xff\xff\xff"),
		.search = "Such horror",
		.output = TEST_CASE_DATA("Such horror "UNICODE_REPLACEMENT_CHAR_UTF8),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{
		/* UTF-8 in content-type parameter */
		.input = TEST_CASE_DATA(
"Content-Type: multipart/mixed; boundary=1; \xF0\x9F\x98\xAD=\"\xF0\x9F\xA5\xBA U+1F62D=U+1F97A\"\n"
"\n--1--\n"),
		.search = "U+1F62D",
		.output = TEST_CASE_DATA("multipart/mixed; boundary=1; \xF0\x9F\x98\xAD=\"\xF0\x9F\xA5\xBA U+1F62D=U+1F97A\""),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "Content-Type",
	},
	{
		/* Broken UTF-8 in content-type parameter */
		.input = TEST_CASE_DATA(
"Content-Type: multipart/mixed; boundary=1;"
" \xFF\xFF\xFF\xFF=\"\xF0\x9F\xA5\xBA U+1F62D=U+1F97A\"\n"
"\n--1--\n"),
		.search = "U+1F62D",
		.output = TEST_CASE_DATA("multipart/mixed; boundary=1; "UNICODE_REPLACEMENT_CHAR_UTF8"=\"\xF0\x9F\xA5\xBA U+1F62D=U+1F97A\""),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "Content-Type",
	},
	{	/* Multipart digest */
		.input = TEST_CASE_DATA(MULTIPART_DIGEST_CORPUS),
		.search = "Not agreeing",
		.output = TEST_CASE_DATA("Not agreeing one bit!"),
		.expect_found = TRUE,
		.expect_body = TRUE,
	},
	{       /* Multipart digest header */
		.input = TEST_CASE_DATA(MULTIPART_DIGEST_CORPUS),
		.search = "someone-else",
		.output = TEST_CASE_DATA("someone-else <someone@else>"),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "From",
	},
	{       /* Multipart digest header parameter */
		.input = TEST_CASE_DATA(MULTIPART_DIGEST_CORPUS),
		.search = "test.txt",
		.output = TEST_CASE_DATA("application/octet-stream; disposition=attachment; name=\"test.txt\""),
		.expect_found = TRUE,
		.expect_body = FALSE,
		.expect_header = TRUE,
		.hdr_name = "Content-Type",
	},
};

	test_begin("message search");

	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) T_BEGIN {
		struct message_search_context *sctx;
		struct message_block raw_block, decoded_block;
		struct message_part *parts;
		const char *error;
		bool found = FALSE;
		const struct test_case *tc = &test_cases[i];
		struct message_parser_settings set = {
			.hdr_flags = MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP,
		};
		pool_t pool = pool_alloconly_create("message parser", 10240);
		struct istream *is =
			test_istream_create_data(tc->input.value, tc->input.value_len);
		struct message_parser_ctx *pctx =
			message_parser_init(pool, is, &set);
		int ret;
		sctx = message_search_init(tc->search, NULL, tc->expect_header ?
					   0 : MESSAGE_SEARCH_FLAG_SKIP_HEADERS);
		while ((ret = message_parser_parse_next_block(pctx, &raw_block)) > 0) {
			if (message_search_more_get_decoded(sctx, &raw_block,
							    &decoded_block)) {
				found = TRUE;
				compare_search_result(tc, &decoded_block, i);
			}
		}
		test_assert_idx(tc->expect_found == found, i);
		message_parser_deinit(&pctx, &parts);
		test_assert(is->stream_errno == 0);
		i_stream_seek(is, 0);
		if ((ret = message_search_msg(sctx, is, parts, &error)) < 0) {
			i_error("Search error: %s", error);
		} else {
			test_assert_idx(tc->expect_found == (ret == 1), i);
		}
		/* and once more */
		i_stream_seek(is, 0);
		if ((ret = message_search_msg(sctx, is, NULL, &error)) < 0) {
			i_error("Search error: %s", error);
		} else {
			test_assert_idx(tc->expect_found == (ret == 1), i);
		}
		message_search_deinit(&sctx);
		test_assert(is->stream_errno == 0);
		i_stream_unref(&is);
		pool_unref(&pool);
	} T_END;

	test_end();

}

static void test_message_search_more_get_decoded(void)
{
	const char input[] = "p\xC3\xB6\xC3\xB6";
	const unsigned char text_plain[] = "text/plain; charset=utf-8";
	struct message_search_context *ctx1, *ctx2;
	struct message_block raw_block, decoded_block;
	struct message_header_line hdr;
	struct message_part part;
	unsigned int i;

	test_begin("message_search_more_get_decoded()");

	ctx1 = message_search_init("p\xC3\xA4\xC3\xA4", NULL, 0);
	ctx2 = message_search_init("p\xC3\xB6\xC3\xB6", NULL, 0);

	i_zero(&raw_block);
	raw_block.part = &part;

	/* feed the Content-Type header */
	i_zero(&hdr);
	hdr.name = "Content-Type"; hdr.name_len = strlen(hdr.name);
	hdr.value = hdr.full_value = text_plain;
	hdr.value_len = hdr.full_value_len = sizeof(text_plain)-1;
	raw_block.hdr = &hdr;
	test_assert(!message_search_more_get_decoded(ctx1, &raw_block, &decoded_block));
	test_assert(!message_search_more_decoded(ctx2, &decoded_block));

	/* EOH */
	raw_block.hdr = NULL;
	test_assert(!message_search_more_get_decoded(ctx1, &raw_block, &decoded_block));
	test_assert(!message_search_more_decoded(ctx2, &decoded_block));

	/* body */
	raw_block.size = 1;
	for (i = 0; input[i] != '\0'; i++) {
		raw_block.data = (const void *)&input[i];
		test_assert(!message_search_more_get_decoded(ctx1, &raw_block, &decoded_block));
		test_assert(message_search_more_decoded(ctx2, &decoded_block) == (input[i+1] == '\0'));
	}
	message_search_deinit(&ctx1);
	message_search_deinit(&ctx2);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_search,
		test_message_search_more_get_decoded,
		NULL
	};
	return test_run(test_functions);
}
