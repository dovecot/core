/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "message-parser.h"
#include "test-common.h"

static const char test_msg[] =
"Return-Path: <test@example.org>\n"
"Subject: Hello world\n"
"From: Test User <test@example.org>\n"
"To: Another User <test2@example.org>\n"
"Message-Id: <1.2.3.4@example>\n"
"Mime-Version: 1.0\n"
"Date: Sun, 23 May 2007 04:58:08 +0300\n"
"Content-Type: multipart/signed; micalg=pgp-sha1;\n"
"	protocol=\"application/pgp-signature\";\n"
"	boundary=\"=-GNQXLhuj24Pl1aCkk4/d\"\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d\n"
"Content-Type: text/plain\n"
"Content-Transfer-Encoding: quoted-printable\n"
"\n"
"There was a day=20\n"
"a happy=20day\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d\n"
"Content-Type: application/pgp-signature; name=signature.asc\n"
"\n"
"-----BEGIN PGP SIGNATURE-----\n"
"Version: GnuPG v1.2.4 (GNU/Linux)\n"
"\n"
"invalid\n"
"-----END PGP SIGNATURE-----\n"
"\n"
"--=-GNQXLhuj24Pl1aCkk4/d--\n"
"\n"
"\n";
#define TEST_MSG_LEN (sizeof(test_msg)-1)

static bool msg_parts_cmp(struct message_part *p1, struct message_part *p2)
{
	while (p1 != NULL || p2 != NULL) {
		if ((p1 != NULL) != (p2 != NULL))
			return FALSE;
		if ((p1->children != NULL) != (p2->children != NULL))
			return FALSE;

		if (p1->children != NULL) {
			if (!msg_parts_cmp(p1->children, p2->children))
				return FALSE;
		}

		if (p1->physical_pos != p2->physical_pos ||
		    p1->header_size.physical_size != p2->header_size.physical_size ||
		    p1->header_size.virtual_size != p2->header_size.virtual_size ||
		    p1->header_size.lines != p2->header_size.lines ||
		    p1->body_size.physical_size != p2->body_size.physical_size ||
		    p1->body_size.virtual_size != p2->body_size.virtual_size ||
		    p1->body_size.lines != p2->body_size.lines ||
		    p1->flags != p2->flags)
			return FALSE;

		p1 = p1->next;
		p2 = p2->next;
	}
	return TRUE;
}

static void test_parsed_parts(struct istream *input, struct message_part *parts)
{
	struct message_parser_ctx *parser;
	struct message_block block;
	struct message_part *parts2;
	uoff_t i, input_size;
	const char *error;

	i_stream_seek(input, 0);
	if (i_stream_get_size(input, TRUE, &input_size) < 0)
		i_unreached();

	parser = message_parser_init_from_parts(parts, input, 0,
					MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK);
	for (i = 1; i <= input_size*2+1; i++) {
		test_istream_set_size(input, i/2);
		if (i > TEST_MSG_LEN*2)
			test_istream_set_allow_eof(input, TRUE);
		while (message_parser_parse_next_block(parser, &block) > 0) ;
	}
	test_assert(message_parser_deinit_from_parts(&parser, &parts2, &error) == 0);
	test_assert(msg_parts_cmp(parts, parts2));
}

static void test_message_parser_small_blocks(void)
{
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts, *parts2;
	struct message_block block;
	unsigned int i, end_of_headers_idx;
	string_t *output;
	pool_t pool;
	const char *error;
	int ret;

	test_begin("message parser in small blocks");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(test_msg);
	output = t_str_new(128);

	/* full parsing */
	parser = message_parser_init(pool, input, 0,
		MESSAGE_PARSER_FLAG_INCLUDE_MULTIPART_BLOCKS |
		MESSAGE_PARSER_FLAG_INCLUDE_BOUNDARIES);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) {
		if (block.hdr != NULL)
			message_header_line_write(output, block.hdr);
		else if (block.size > 0)
			str_append_data(output, block.data, block.size);
	}

	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);
	test_assert(strcmp(test_msg, str_c(output)) == 0);

	/* parsing in small blocks */
	i_stream_seek(input, 0);
	test_istream_set_allow_eof(input, FALSE);

	parser = message_parser_init(pool, input, 0, 0);
	for (i = 1; i <= TEST_MSG_LEN*2+1; i++) {
		test_istream_set_size(input, i/2);
		if (i > TEST_MSG_LEN*2)
			test_istream_set_allow_eof(input, TRUE);
		while ((ret = message_parser_parse_next_block(parser,
							      &block)) > 0) ;
		test_assert((ret == 0 && i <= TEST_MSG_LEN*2) ||
			    (ret < 0 && i > TEST_MSG_LEN*2));
	}
	message_parser_deinit(&parser, &parts2);
	test_assert(msg_parts_cmp(parts, parts2));

	/* parsing in small blocks from preparsed parts */
	i_stream_seek(input, 0);
	test_istream_set_allow_eof(input, FALSE);

	end_of_headers_idx = (strstr(test_msg, "\n-----") - test_msg);
	parser = message_parser_init_from_parts(parts, input, 0,
					MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK);
	for (i = 1; i <= TEST_MSG_LEN*2+1; i++) {
		test_istream_set_size(input, i/2);
		if (i > TEST_MSG_LEN*2)
			test_istream_set_allow_eof(input, TRUE);
		while ((ret = message_parser_parse_next_block(parser,
							      &block)) > 0) ;
		test_assert((ret == 0 && i/2 <= end_of_headers_idx) ||
			    (ret < 0 && i/2 > end_of_headers_idx));
	}
	test_assert(message_parser_deinit_from_parts(&parser, &parts2, &error) == 0);
	test_assert(msg_parts_cmp(parts, parts2));

	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_truncated_mime_headers(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\":foo\"\n"
"\n"
"--:foo\n"
"--:foo\n"
"Content-Type: text/plain\n"
"--:foo\n"
"Content-Type: text/plain\r\n"
"--:foo\n"
"Content-Type: text/html\n"
"--:foo--\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts, *part;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser truncated mime headers");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);

	test_assert((parts->flags & MESSAGE_PART_FLAG_MULTIPART) != 0);
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 48);
	test_assert(parts->header_size.virtual_size == 48+2);
	test_assert(parts->body_size.lines == 8);
	test_assert(parts->body_size.physical_size == 112);
	test_assert(parts->body_size.virtual_size == 112+7);
	test_assert(parts->children->physical_pos == 55);
	test_assert(parts->children->header_size.physical_size == 0);
	test_assert(parts->children->body_size.physical_size == 0);
	test_assert(parts->children->body_size.lines == 0);
	test_assert(parts->children->next->physical_pos == 62);
	test_assert(parts->children->next->header_size.physical_size == 24);
	test_assert(parts->children->next->header_size.virtual_size == 24);
	test_assert(parts->children->next->header_size.lines == 0);
	test_assert(parts->children->next->next->physical_pos == 94);
	test_assert(parts->children->next->next->header_size.physical_size == 24);
	test_assert(parts->children->next->next->header_size.virtual_size == 24);
	test_assert(parts->children->next->next->header_size.lines == 0);
	test_assert(parts->children->next->next->next->physical_pos == 127);
	test_assert(parts->children->next->next->next->header_size.physical_size == 23);
	test_assert(parts->children->next->next->next->header_size.virtual_size == 23);
	test_assert(parts->children->next->next->next->header_size.lines == 0);
	for (part = parts->children; part != NULL; part = part->next) {
		test_assert(part->body_size.physical_size == 0);
		test_assert(part->body_size.virtual_size == 0);
	}
	test_assert(parts->children->next->next->next->next == NULL);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_truncated_mime_headers2(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"ab\"\n"
"\n"
"--ab\n"
"Content-Type: multipart/mixed; boundary=\"a\"\n"
"\n"
"--ab\n"
"Content-Type: text/plain\n"
"\n"
"--a\n\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser truncated mime headers 2");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);

	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 46);
	test_assert(parts->header_size.virtual_size == 46+2);
	test_assert(parts->body_size.lines == 8);
	test_assert(parts->body_size.physical_size == 86);
	test_assert(parts->body_size.virtual_size == 86+8);

	test_assert(parts->children->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->physical_pos == 51);
	test_assert(parts->children->header_size.lines == 1);
	test_assert(parts->children->header_size.physical_size == 44);
	test_assert(parts->children->header_size.virtual_size == 44+1);
	test_assert(parts->children->body_size.lines == 0);
	test_assert(parts->children->body_size.physical_size == 0);
	test_assert(parts->children->children == NULL);

	test_assert(parts->children->next->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->next->physical_pos == 101);
	test_assert(parts->children->next->header_size.lines == 2);
	test_assert(parts->children->next->header_size.physical_size == 26);
	test_assert(parts->children->next->header_size.virtual_size == 26+2);
	test_assert(parts->children->next->body_size.lines == 2);
	test_assert(parts->children->next->body_size.physical_size == 5);
	test_assert(parts->children->next->body_size.virtual_size == 5+2);
	test_assert(parts->children->next->children == NULL);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_truncated_mime_headers3(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"ab\"\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser truncated mime headers 3");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);

	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 1);
	test_assert(parts->header_size.physical_size == 45);
	test_assert(parts->header_size.virtual_size == 45+1);
	test_assert(parts->body_size.lines == 0);
	test_assert(parts->body_size.physical_size == 0);

	test_assert(parts->children == NULL);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_empty_multipart(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"ab\"\n"
"\n"
"body\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser empty multipart");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);

	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 46);
	test_assert(parts->header_size.virtual_size == 46+2);
	test_assert(parts->body_size.lines == 1);
	test_assert(parts->body_size.physical_size == 5);
	test_assert(parts->body_size.virtual_size == 5+1);

	test_assert(parts->children == NULL);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_duplicate_mime_boundary(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"a\"\n"
"\n"
"--a\n"
"Content-Type: multipart/mixed; boundary=\"a\"\n"
"\n"
"--a\n"
"Content-Type: text/plain\n"
"\n"
"body\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser duplicate mime boundary");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);

	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 45);
	test_assert(parts->header_size.virtual_size == 45+2);
	test_assert(parts->body_size.lines == 7);
	test_assert(parts->body_size.physical_size == 84);
	test_assert(parts->body_size.virtual_size == 84+7);
	test_assert(parts->children->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->physical_pos == 49);
	test_assert(parts->children->header_size.lines == 2);
	test_assert(parts->children->header_size.physical_size == 45);
	test_assert(parts->children->header_size.virtual_size == 45+2);
	test_assert(parts->children->body_size.lines == 4);
	test_assert(parts->children->body_size.physical_size == 35);
	test_assert(parts->children->body_size.virtual_size == 35+4);
	test_assert(parts->children->children->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->children->physical_pos == 98);
	test_assert(parts->children->children->header_size.lines == 2);
	test_assert(parts->children->children->header_size.physical_size == 26);
	test_assert(parts->children->children->header_size.virtual_size == 26+2);
	test_assert(parts->children->children->body_size.lines == 1);
	test_assert(parts->children->children->body_size.physical_size == 5);
	test_assert(parts->children->children->body_size.virtual_size == 5+1);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_garbage_suffix_mime_boundary(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"a\"\n"
"\n"
"--ab\n"
"Content-Type: multipart/mixed; boundary=\"a\"\n"
"\n"
"--ac\n"
"Content-Type: text/plain\n"
"\n"
"body\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser garbage suffix mime boundary");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);

	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 45);
	test_assert(parts->header_size.virtual_size == 45+2);
	test_assert(parts->body_size.lines == 7);
	test_assert(parts->body_size.physical_size == 86);
	test_assert(parts->body_size.virtual_size == 86+7);
	test_assert(parts->children->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->physical_pos == 50);
	test_assert(parts->children->header_size.lines == 2);
	test_assert(parts->children->header_size.physical_size == 45);
	test_assert(parts->children->header_size.virtual_size == 45+2);
	test_assert(parts->children->body_size.lines == 4);
	test_assert(parts->children->body_size.physical_size == 36);
	test_assert(parts->children->body_size.virtual_size == 36+4);
	test_assert(parts->children->children->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->children->physical_pos == 100);
	test_assert(parts->children->children->header_size.lines == 2);
	test_assert(parts->children->children->header_size.physical_size == 26);
	test_assert(parts->children->children->header_size.virtual_size == 26+2);
	test_assert(parts->children->children->body_size.lines == 1);
	test_assert(parts->children->children->body_size.physical_size == 5);
	test_assert(parts->children->children->body_size.virtual_size == 5+1);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_continuing_mime_boundary(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"a\"\n"
"\n"
"--a\n"
"Content-Type: multipart/mixed; boundary=\"ab\"\n"
"\n"
"--ab\n"
"Content-Type: text/plain\n"
"\n"
"body\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser continuing mime boundary");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);

	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 45);
	test_assert(parts->header_size.virtual_size == 45+2);
	test_assert(parts->body_size.lines == 7);
	test_assert(parts->body_size.physical_size == 86);
	test_assert(parts->body_size.virtual_size == 86+7);
	test_assert(parts->children->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->physical_pos == 49);
	test_assert(parts->children->header_size.lines == 2);
	test_assert(parts->children->header_size.physical_size == 46);
	test_assert(parts->children->header_size.virtual_size == 46+2);
	test_assert(parts->children->body_size.lines == 4);
	test_assert(parts->children->body_size.physical_size == 36);
	test_assert(parts->children->body_size.virtual_size == 36+4);
	test_assert(parts->children->children->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->children->physical_pos == 100);
	test_assert(parts->children->children->header_size.lines == 2);
	test_assert(parts->children->children->header_size.physical_size == 26);
	test_assert(parts->children->children->header_size.virtual_size == 26+2);
	test_assert(parts->children->children->body_size.lines == 1);
	test_assert(parts->children->children->body_size.physical_size == 5);
	test_assert(parts->children->children->body_size.virtual_size == 5+1);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_continuing_truncated_mime_boundary(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"a\"\n"
"\n"
"--a\n"
"Content-Type: multipart/mixed; boundary=\"ab\"\n"
"MIME-Version: 1.0\n"
"--ab\n"
"Content-Type: text/plain\n"
"\n"
"--ab--\n"
"--a--\n\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts, *part;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser continuing truncated mime boundary");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);

	part = parts;
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 45);
	test_assert(part->header_size.virtual_size == 45+2);
	test_assert(part->body_size.lines == 9);
	test_assert(part->body_size.physical_size == 112);
	test_assert(part->body_size.virtual_size == 112+9);

	part = parts->children;
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->physical_pos == 49);
	test_assert(part->header_size.lines == 1);
	test_assert(part->header_size.physical_size == 45+17);
	test_assert(part->header_size.virtual_size == 45+17+1);
	test_assert(part->body_size.lines == 0);
	test_assert(part->body_size.physical_size == 0);
	test_assert(part->children == NULL);

	/* this will not be a child, since the header was truncated. I guess
	   we could make it, but it would complicate the message-parser even
	   more. */
	part = parts->children->next;
	test_assert(part->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->physical_pos == 117);
	test_assert(part->header_size.lines == 1);
	test_assert(part->header_size.physical_size == 25);
	test_assert(part->header_size.virtual_size == 25+1);
	test_assert(part->body_size.lines == 0);
	test_assert(part->body_size.physical_size == 0);
	test_assert(part->children == NULL);

	part = parts->children->next->next;
	test_assert(part->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 0);
	test_assert(part->header_size.physical_size == 0);
	test_assert(part->body_size.lines == 0);
	test_assert(part->body_size.physical_size == 0);
	test_assert(part->children == NULL);
	test_assert(part->next == NULL);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_no_eoh(void)
{
	static const char input_msg[] = "a:b\n";
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts;
	struct message_block block;
	pool_t pool;

	test_begin("message parser no EOH");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, 0, 0);
	test_assert(message_parser_parse_next_block(parser, &block) > 0 &&
		    block.hdr != NULL && strcmp(block.hdr->name, "a") == 0 &&
		    block.hdr->value_len == 1 && block.hdr->value[0] == 'b');
	test_assert(message_parser_parse_next_block(parser, &block) > 0 &&
		    block.hdr == NULL && block.size == 0);
	test_assert(message_parser_parse_next_block(parser, &block) < 0);
	message_parser_deinit(&parser, &parts);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_parser_small_blocks,
		test_message_parser_truncated_mime_headers,
		test_message_parser_truncated_mime_headers2,
		test_message_parser_truncated_mime_headers3,
		test_message_parser_empty_multipart,
		test_message_parser_duplicate_mime_boundary,
		test_message_parser_garbage_suffix_mime_boundary,
		test_message_parser_continuing_mime_boundary,
		test_message_parser_continuing_truncated_mime_boundary,
		test_message_parser_no_eoh,
		NULL
	};
	return test_run(test_functions);
}
