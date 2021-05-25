/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "message-parser.h"
#include "message-part-data.h"
#include "message-size.h"
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

static const struct message_parser_settings set_empty = { .flags = 0 };

static int message_parse_stream(pool_t pool, struct istream *input,
				const struct message_parser_settings *set,
				bool parse_data, struct message_part **parts_r)
{
	int ret;
	struct message_parser_ctx *parser;
	struct message_block block;

	i_zero(&block);
	parser = message_parser_init(pool, input, set);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0)
		if (parse_data)
			message_part_data_parse_from_header(pool, block.part,
							    block.hdr);
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
	uoff_t i, input_size;
	const char *error;

	i_stream_seek(input, 0);
	if (i_stream_get_size(input, TRUE, &input_size) < 0)
		i_unreached();

	parser = message_parser_init_from_parts(parts, input, &parser_set);
	for (i = 1; i <= input_size*2+1; i++) {
		test_istream_set_size(input, i/2);
		if (i > TEST_MSG_LEN*2)
			test_istream_set_allow_eof(input, TRUE);
		while (message_parser_parse_next_block(parser, &block) > 0) ;
	}
	test_assert(message_parser_deinit_from_parts(&parser, &parts2, &error) == 0);
	test_assert(message_part_is_equal(parts, parts2));
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
	const struct message_parser_settings full_parser_set = {
		.flags = MESSAGE_PARSER_FLAG_INCLUDE_MULTIPART_BLOCKS |
			MESSAGE_PARSER_FLAG_INCLUDE_BOUNDARIES,
	};
	parser = message_parser_init(pool, input, &full_parser_set);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) {
		if (block.hdr != NULL)
			message_header_line_write(output, block.hdr);
		else if (block.size > 0)
			str_append_data(output, block.data, block.size);
	}

	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);
	test_assert(input->stream_errno == 0);
	test_assert(strcmp(test_msg, str_c(output)) == 0);

	/* parsing in small blocks */
	i_stream_seek(input, 0);
	test_istream_set_allow_eof(input, FALSE);

	parser = message_parser_init(pool, input, &set_empty);
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
	test_assert(input->stream_errno == 0);
	test_assert(message_part_is_equal(parts, parts2));

	/* parsing in small blocks from preparsed parts */
	i_stream_seek(input, 0);
	test_istream_set_allow_eof(input, FALSE);

	end_of_headers_idx = (strstr(test_msg, "\n-----") - test_msg);
	const struct message_parser_settings preparsed_parser_set = {
		.flags = MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK,
	};
	parser = message_parser_init_from_parts(parts, input,
						&preparsed_parser_set);
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
	test_assert(message_part_is_equal(parts, parts2));

	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_stop_early(void)
{
	struct istream *input, *input2;
	struct message_part *parts;
	unsigned int i;
	pool_t pool;

	test_begin("message parser in stop early");
	pool = pool_alloconly_create("message parser", 524288);
	input = test_istream_create(test_msg);

	test_istream_set_allow_eof(input, FALSE);
	for (i = 1; i <= TEST_MSG_LEN+1; i++) {
		i_stream_seek(input, 0);
		test_istream_set_size(input, i);

		test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) == 0);

		/* test preparsed - first re-parse everything with a stream
		   that sees EOF at this position */
		input2 = i_stream_create_from_data(test_msg, i);
		test_assert(message_parse_stream(pool, input2, &set_empty, FALSE, &parts) == -1);

		/* now parse from the parts */
		i_stream_seek(input2, 0);
		test_assert(message_parse_stream(pool, input2, &set_empty, FALSE, &parts) == -1);

		i_stream_unref(&input2);
	}

	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_get_sizes(struct istream *input,
					  struct message_size *body_size_r,
					  struct message_size *header_size_r,
					  bool expect_has_nuls)
{
	bool has_nuls;
	i_zero(body_size_r);
	i_zero(header_size_r);

	message_get_header_size(input, header_size_r, &has_nuls);
	test_assert(has_nuls == expect_has_nuls);
	message_get_body_size(input, body_size_r, &has_nuls);
	test_assert(has_nuls == expect_has_nuls);
}

static void test_message_parser_assert_sizes(const struct message_part *part,
					     const struct message_size *body_size,
					     const struct message_size *header_size)
{
	test_assert(part->header_size.lines == header_size->lines);
	test_assert(part->header_size.physical_size == header_size->physical_size);
	test_assert(part->header_size.virtual_size == header_size->virtual_size);
	test_assert(part->body_size.lines == body_size->lines);
	test_assert(part->body_size.physical_size == body_size->physical_size);
	test_assert(part->body_size.virtual_size == body_size->virtual_size);
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
	struct istream *input;
	struct message_part *parts, *part;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser truncated mime headers");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	test_assert((parts->flags & MESSAGE_PART_FLAG_MULTIPART) != 0);
	test_assert(parts->children_count == 4);
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 48);
	test_assert(parts->header_size.virtual_size == 48+2);
	test_assert(parts->body_size.lines == 8);
	test_assert(parts->body_size.physical_size == 112);
	test_assert(parts->body_size.virtual_size == 112+7);
	test_message_parser_assert_sizes(parts, &body_size, &header_size);

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
		test_assert(part->children_count == 0);
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
	struct istream *input;
	struct message_part *parts;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser truncated mime headers 2");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children_count == 2);
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 46);
	test_assert(parts->header_size.virtual_size == 46+2);
	test_assert(parts->body_size.lines == 8);
	test_assert(parts->body_size.physical_size == 86);
	test_assert(parts->body_size.virtual_size == 86+8);
	test_message_parser_assert_sizes(parts, &body_size, &header_size);

	test_assert(parts->children->children_count == 0);
	test_assert(parts->children->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->physical_pos == 51);
	test_assert(parts->children->header_size.lines == 1);
	test_assert(parts->children->header_size.physical_size == 44);
	test_assert(parts->children->header_size.virtual_size == 44+1);
	test_assert(parts->children->body_size.lines == 0);
	test_assert(parts->children->body_size.physical_size == 0);
	test_assert(parts->children->children == NULL);

	test_assert(parts->children->next->children_count == 0);
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
	struct istream *input;
	struct message_part *parts;
	pool_t pool;

	test_begin("message parser truncated mime headers 3");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	test_assert(parts->children_count == 0);
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
	struct istream *input;
	struct message_part *parts;
	pool_t pool;

	test_begin("message parser empty multipart");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	test_assert(parts->children_count == 0);
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
	struct istream *input;
	struct message_part *parts;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser duplicate mime boundary");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	test_assert(parts->children_count == 2);
	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 45);
	test_assert(parts->header_size.virtual_size == 45+2);
	test_assert(parts->body_size.lines == 7);
	test_assert(parts->body_size.physical_size == 84);
	test_assert(parts->body_size.virtual_size == 84+7);
	test_message_parser_assert_sizes(parts, &body_size, &header_size);

	test_assert(parts->children->children_count == 1);
	test_assert(parts->children->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->physical_pos == 49);
	test_assert(parts->children->header_size.lines == 2);
	test_assert(parts->children->header_size.physical_size == 45);
	test_assert(parts->children->header_size.virtual_size == 45+2);
	test_assert(parts->children->body_size.lines == 4);
	test_assert(parts->children->body_size.physical_size == 35);
	test_assert(parts->children->body_size.virtual_size == 35+4);
	test_assert(parts->children->children->children_count == 0);
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
	struct istream *input;
	struct message_part *parts;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser garbage suffix mime boundary");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	test_assert(parts->children_count == 2);
	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 45);
	test_assert(parts->header_size.virtual_size == 45+2);
	test_assert(parts->body_size.lines == 7);
	test_assert(parts->body_size.physical_size == 86);
	test_assert(parts->body_size.virtual_size == 86+7);
	test_message_parser_assert_sizes(parts, &body_size, &header_size);

	test_assert(parts->children->children_count == 1);
	test_assert(parts->children->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->physical_pos == 50);
	test_assert(parts->children->header_size.lines == 2);
	test_assert(parts->children->header_size.physical_size == 45);
	test_assert(parts->children->header_size.virtual_size == 45+2);
	test_assert(parts->children->body_size.lines == 4);
	test_assert(parts->children->body_size.physical_size == 36);
	test_assert(parts->children->body_size.virtual_size == 36+4);
	test_assert(parts->children->children->children_count == 0);
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

static void test_message_parser_trailing_dashes(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"a--\"\n"
"\n"
"--a--\n"
"Content-Type: multipart/mixed; boundary=\"a----\"\n"
"\n"
"--a----\n"
"Content-Type: text/plain\n"
"\n"
"body\n"
"--a------\n"
"Content-Type: text/html\n"
"\n"
"body2\n"
"--a----";
	struct istream *input;
	struct message_part *parts;
	pool_t pool;

	test_begin("message parser trailing dashes");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	test_assert(parts->children_count == 2);
	test_assert(parts->children->next == NULL);
	test_assert(parts->children->children_count == 1);
	test_assert(parts->children->children->next == NULL);
	test_assert(parts->children->children->children_count == 0);

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
	struct istream *input;
	struct message_part *parts;
	pool_t pool;

	test_begin("message parser continuing mime boundary");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	i_stream_seek(input, 0);

	test_assert(parts->children_count == 2);
	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 45);
	test_assert(parts->header_size.virtual_size == 45+2);
	test_assert(parts->body_size.lines == 7);
	test_assert(parts->body_size.physical_size == 86);
	test_assert(parts->body_size.virtual_size == 86+7);
	test_assert(parts->children->children_count == 1);
	test_assert(parts->children->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->physical_pos == 49);
	test_assert(parts->children->header_size.lines == 2);
	test_assert(parts->children->header_size.physical_size == 46);
	test_assert(parts->children->header_size.virtual_size == 46+2);
	test_assert(parts->children->body_size.lines == 4);
	test_assert(parts->children->body_size.physical_size == 36);
	test_assert(parts->children->body_size.virtual_size == 36+4);
	test_assert(parts->children->children->children_count == 0);
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
	struct istream *input;
	struct message_part *parts, *part;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser continuing truncated mime boundary");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	part = parts;
	test_assert(part->children_count == 3);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 45);
	test_assert(part->header_size.virtual_size == 45+2);
	test_assert(part->body_size.lines == 9);
	test_assert(part->body_size.physical_size == 112);
	test_assert(part->body_size.virtual_size == 112+9);
	test_message_parser_assert_sizes(part, &body_size, &header_size);

	part = parts->children;
	test_assert(part->children_count == 0);
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
	test_assert(part->children_count == 0);
	test_assert(part->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->physical_pos == 117);
	test_assert(part->header_size.lines == 1);
	test_assert(part->header_size.physical_size == 25);
	test_assert(part->header_size.virtual_size == 25+1);
	test_assert(part->body_size.lines == 0);
	test_assert(part->body_size.physical_size == 0);
	test_assert(part->children == NULL);

	part = parts->children->next->next;
	test_assert(part->children_count == 0);
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

static void test_message_parser_continuing_mime_boundary_reverse(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"ab\"\n"
"\n"
"--ab\n"
"Content-Type: multipart/mixed; boundary=\"a\"\n"
"\n"
"--a\n"
"Content-Type: text/plain\n"
"\n"
"body\n"
"--ab\n"
"Content-Type: text/html\n"
"\n"
"body2\n";
	struct istream *input;
	struct message_part *parts;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser continuing mime boundary reverse");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	test_assert(parts->children_count == 3);
	test_assert(parts->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->header_size.lines == 2);
	test_assert(parts->header_size.physical_size == 46);
	test_assert(parts->header_size.virtual_size == 46+2);
	test_assert(parts->body_size.lines == 11);
	test_assert(parts->body_size.physical_size == 121);
	test_assert(parts->body_size.virtual_size == 121+11);
	test_message_parser_assert_sizes(parts, &body_size, &header_size);

	test_assert(parts->children->children_count == 1);
	test_assert(parts->children->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->physical_pos == 51);
	test_assert(parts->children->header_size.lines == 2);
	test_assert(parts->children->header_size.physical_size == 45);
	test_assert(parts->children->header_size.virtual_size == 45+2);
	test_assert(parts->children->body_size.lines == 3);
	test_assert(parts->children->body_size.physical_size == 34);
	test_assert(parts->children->body_size.virtual_size == 34+3);
	test_assert(parts->children->children->children_count == 0);
	test_assert(parts->children->children->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->children->physical_pos == 100);
	test_assert(parts->children->children->header_size.lines == 2);
	test_assert(parts->children->children->header_size.physical_size == 26);
	test_assert(parts->children->children->header_size.virtual_size == 26+2);
	test_assert(parts->children->children->body_size.lines == 0);
	test_assert(parts->children->children->body_size.physical_size == 4);
	test_assert(parts->children->children->body_size.virtual_size == 4);
	test_assert(parts->children->next->children_count == 0);
	test_assert(parts->children->next->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(parts->children->next->physical_pos == 136);
	test_assert(parts->children->next->header_size.lines == 2);
	test_assert(parts->children->next->header_size.physical_size == 25);
	test_assert(parts->children->next->header_size.virtual_size == 25+2);
	test_assert(parts->children->next->body_size.lines == 1);
	test_assert(parts->children->next->body_size.physical_size == 6);
	test_assert(parts->children->next->body_size.virtual_size == 6+1);

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

	parser = message_parser_init(pool, input, &set_empty);
	test_assert(message_parser_parse_next_block(parser, &block) > 0 &&
		    block.hdr != NULL && strcmp(block.hdr->name, "a") == 0 &&
		    block.hdr->value_len == 1 && block.hdr->value[0] == 'b');
	test_assert(message_parser_parse_next_block(parser, &block) > 0 &&
		    block.hdr == NULL && block.size == 0);
	test_assert(message_parser_parse_next_block(parser, &block) < 0);
	message_parser_deinit(&parser, &parts);
	test_assert(input->stream_errno == 0);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_long_mime_boundary(void)
{
	/* Close the boundaries in wrong reverse order. But because all
	   boundaries are actually truncated to the same size (..890) it
	   works the same as if all of them were duplicate boundaries. */
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"1234567890123456789012345678901234567890123456789012345678901234567890123456789012\"\n"
"\n"
"--1234567890123456789012345678901234567890123456789012345678901234567890123456789012\n"
"Content-Type: multipart/mixed; boundary=\"123456789012345678901234567890123456789012345678901234567890123456789012345678901\"\n"
"\n"
"--123456789012345678901234567890123456789012345678901234567890123456789012345678901\n"
"Content-Type: multipart/mixed; boundary=\"12345678901234567890123456789012345678901234567890123456789012345678901234567890\"\n"
"\n"
"--12345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
"Content-Type: text/plain\n"
"\n"
"1\n"
"--1234567890123456789012345678901234567890123456789012345678901234567890123456789012\n"
"Content-Type: text/plain\n"
"\n"
"22\n"
"--123456789012345678901234567890123456789012345678901234567890123456789012345678901\n"
"Content-Type: text/plain\n"
"\n"
"333\n"
"--12345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
"Content-Type: text/plain\n"
"\n"
"4444\n";
	struct istream *input;
	struct message_part *parts, *part;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser long mime boundary");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &set_empty, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	part = parts;
	test_assert(part->children_count == 6);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 126);
	test_assert(part->header_size.virtual_size == 126+2);
	test_assert(part->body_size.lines == 22);
	test_assert(part->body_size.physical_size == 871);
	test_assert(part->body_size.virtual_size == 871+22);
	test_message_parser_assert_sizes(part, &body_size, &header_size);

	part = parts->children;
	test_assert(part->children_count == 5);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 125);
	test_assert(part->header_size.virtual_size == 125+2);
	test_assert(part->body_size.lines == 19);
	test_assert(part->body_size.physical_size == 661);
	test_assert(part->body_size.virtual_size == 661+19);

	part = parts->children->children;
	test_assert(part->children_count == 4);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 124);
	test_assert(part->header_size.virtual_size == 124+2);
	test_assert(part->body_size.lines == 16);
	test_assert(part->body_size.physical_size == 453);
	test_assert(part->body_size.virtual_size == 453+16);

	part = parts->children->children->children;
	for (unsigned int i = 1; i <= 3; i++, part = part->next) {
		test_assert(part->children_count == 0);
		test_assert(part->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
		test_assert(part->header_size.lines == 2);
		test_assert(part->header_size.physical_size == 26);
		test_assert(part->header_size.virtual_size == 26+2);
		test_assert(part->body_size.lines == 0);
		test_assert(part->body_size.physical_size == i);
		test_assert(part->body_size.virtual_size == i);
	}

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_mime_part_nested_limit(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"1\"\n"
"\n"
"--1\n"
"Content-Type: multipart/mixed; boundary=\"2\"\n"
"\n"
"--2\n"
"Content-Type: text/plain\n"
"\n"
"1\n"
"--2\n"
"Content-Type: text/plain\n"
"\n"
"22\n"
"--1\n"
"Content-Type: text/plain\n"
"\n"
"333\n";
	const struct message_parser_settings parser_set = {
		.max_nested_mime_parts = 2,
	};
	struct istream *input;
	struct message_part *parts, *part;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser mime part nested limit");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &parser_set, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	part = parts;
	test_assert(part->children_count == 2);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 45);
	test_assert(part->header_size.virtual_size == 45+2);
	test_assert(part->body_size.lines == 15);
	test_assert(part->body_size.physical_size == 148);
	test_assert(part->body_size.virtual_size == 148+15);
	test_message_parser_assert_sizes(part, &body_size, &header_size);

	part = parts->children;
	test_assert(part->children_count == 0);
	test_assert(part->flags == (MESSAGE_PART_FLAG_IS_MIME |
				    MESSAGE_PART_FLAG_OVERFLOW));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 45);
	test_assert(part->header_size.virtual_size == 45+2);
	test_assert(part->body_size.lines == 7);
	test_assert(part->body_size.physical_size == 64);
	test_assert(part->body_size.virtual_size == 64+7);

	part = parts->children->next;
	test_assert(part->children_count == 0);
	test_assert(part->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 26);
	test_assert(part->header_size.virtual_size == 26+2);
	test_assert(part->body_size.lines == 1);
	test_assert(part->body_size.physical_size == 4);
	test_assert(part->body_size.virtual_size == 4+1);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_mime_part_nested_limit_rfc822(void)
{
static const char input_msg[] =
"Content-Type: message/rfc822\n"
"\n"
"Content-Type: message/rfc822\n"
"\n"
"Content-Type: text/plain\n"
"\n"
"1\n";
	const struct message_parser_settings parser_set = {
		.max_nested_mime_parts = 2,
	};
	struct istream *input;
	struct message_part *parts, *part;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser mime part nested limit rfc822");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &parser_set, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	part = parts;
	test_assert(part->children_count == 1);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MESSAGE_RFC822 | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 30);
	test_assert(part->header_size.virtual_size == 30+2);
	test_assert(part->body_size.lines == 5);
	test_assert(part->body_size.physical_size == 58);
	test_assert(part->body_size.virtual_size == 58+5);
	test_message_parser_assert_sizes(part, &body_size, &header_size);

	part = parts->children;
	test_assert(part->children_count == 0);
	test_assert(part->flags == (MESSAGE_PART_FLAG_IS_MIME |
				    MESSAGE_PART_FLAG_OVERFLOW));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 30);
	test_assert(part->header_size.virtual_size == 30+2);
	test_assert(part->body_size.lines == 3);
	test_assert(part->body_size.physical_size == 28);
	test_assert(part->body_size.virtual_size == 28+3);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_mime_part_limit(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"1\"\n"
"\n"
"--1\n"
"Content-Type: multipart/mixed; boundary=\"2\"\n"
"\n"
"--2\n"
"Content-Type: text/plain\n"
"\n"
"1\n"
"--2\n"
"Content-Type: text/plain\n"
"\n"
"22\n"
"--1\n"
"Content-Type: text/plain\n"
"\n"
"333\n";
	const struct message_parser_settings parser_set = {
		.max_total_mime_parts = 4,
	};
	struct istream *input;
	struct message_part *parts, *part;
	struct message_size body_size, header_size;
	pool_t pool;

	test_begin("message parser mime part limit");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &parser_set, FALSE, &parts) < 0);

	i_stream_seek(input, 0);
	test_message_parser_get_sizes(input, &body_size, &header_size, FALSE);

	part = parts;
	test_assert(part->children_count == 3);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 45);
	test_assert(part->header_size.virtual_size == 45+2);
	test_assert(part->body_size.lines == 15);
	test_assert(part->body_size.physical_size == 148);
	test_assert(part->body_size.virtual_size == 148+15);
	test_message_parser_assert_sizes(part, &body_size, &header_size);

	part = parts->children;
	test_assert(part->children_count == 2);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 45);
	test_assert(part->header_size.virtual_size == 45+2);
	test_assert(part->body_size.lines == 12);
	test_assert(part->body_size.physical_size == 99);
	test_assert(part->body_size.virtual_size == 99+12);

	part = parts->children->children;
	test_assert(part->children_count == 0);
	test_assert(part->flags == (MESSAGE_PART_FLAG_TEXT | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 26);
	test_assert(part->header_size.virtual_size == 26+2);
	test_assert(part->body_size.lines == 0);
	test_assert(part->body_size.physical_size == 1);
	test_assert(part->body_size.virtual_size == 1);

	part = parts->children->children->next;
	test_assert(part->children_count == 0);
	test_assert(part->flags == (MESSAGE_PART_FLAG_TEXT |
				    MESSAGE_PART_FLAG_IS_MIME |
				    MESSAGE_PART_FLAG_OVERFLOW));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 26);
	test_assert(part->header_size.virtual_size == 26+2);
	test_assert(part->body_size.lines == 5);
	test_assert(part->body_size.physical_size == 37);
	test_assert(part->body_size.virtual_size == 37+5);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_mime_part_limit_rfc822(void)
{
static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"1\"\n"
"\n"
"--1\n"
"Content-Type: multipart/mixed; boundary=\"2\"\n"
"\n"
"--2\n"
"Content-Type: message/rfc822\n"
"\n"
"Content-Type: text/plain\n"
"\n"
"1\n"
"--2\n"
"Content-Type: message/rfc822\n"
"\n"
"Content-Type: text/plain\n"
"\n"
"22\n"
"--1\n"
"Content-Type: message/rfc822\n"
"\n"
"Content-Type: text/plain\n"
"\n"
"333\n";
	const struct message_parser_settings parser_set = {
		.max_total_mime_parts = 3,
	};
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts, *part;
	struct message_block block;
	pool_t pool;
	int ret;

	test_begin("message parser mime part limit rfc822");
	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	parser = message_parser_init(pool, input, &parser_set);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	test_assert(ret < 0);
	message_parser_deinit(&parser, &parts);

	part = parts;
	test_assert(part->children_count == 2);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 45);
	test_assert(part->header_size.virtual_size == 45+2);
	test_assert(part->body_size.lines == 21);
	test_assert(part->body_size.physical_size == 238);
	test_assert(part->body_size.virtual_size == 238+21);

	part = parts->children;
	test_assert(part->children_count == 1);
	test_assert(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 45);
	test_assert(part->header_size.virtual_size == 45+2);
	test_assert(part->body_size.lines == 18);
	test_assert(part->body_size.physical_size == 189);
	test_assert(part->body_size.virtual_size == 189+18);

	part = parts->children->children;
	test_assert(part->children_count == 0);
	test_assert(part->flags == (MESSAGE_PART_FLAG_IS_MIME |
				    MESSAGE_PART_FLAG_OVERFLOW));
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 30);
	test_assert(part->header_size.virtual_size == 30+2);
	test_assert(part->body_size.lines == 15);
	test_assert(part->body_size.physical_size == 155);
	test_assert(part->body_size.virtual_size == 155+15);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_mime_version(void)
{
	test_begin("message parser mime version");

	/* Check that MIME version is accepted. */
static const char *const input_msgs[] = {
	/* valid mime header */
"Content-Type: multipart/mixed; boundary=\"1\"\n"
"MIME-Version: 1.0\n\n"
"--1\n"
"Content-Type: text/plain\n"
"\n"
"hello, world\n"
"--1\n",
	/* future mime header */
"Content-Type: multipart/mixed; boundary=\"1\"\n"
"MIME-Version: 2.0\n\n"
"--1\n"
"Content-Type: text/plain\n"
"\n"
"hello, world\n"
"--1\n",
	/* invalid value in mime header */
"Content-Type: multipart/mixed; boundary=\"1\"\n"
"MIME-Version: abc\n\n"
"--1\n"
"Content-Type: text/plain\n"
"\n"
"hello, world\n"
"--1\n",
	/* missing value in mime header */
"Content-Type: multipart/mixed; boundary=\"1\"\n"
"MIME-Version:\n\n"
"--1\n"
"Content-Type: text/plain\n"
"\n"
"hello, world\n"
"--1\n"
	};

	const struct message_parser_settings parser_set = {
		.max_total_mime_parts = 2,
		.flags = MESSAGE_PARSER_FLAG_MIME_VERSION_STRICT,
	};
	struct istream *input;
	struct message_part *parts, *part;
	pool_t pool;

	for (size_t i = 0; i < N_ELEMENTS(input_msgs); i++) {
		ssize_t variance = (ssize_t)strlen(input_msgs[i]) - (ssize_t)strlen(input_msgs[0]);
		pool = pool_alloconly_create("message parser", 10240);
		input = test_istream_create(input_msgs[i]);

		test_assert(message_parse_stream(pool, input, &parser_set, TRUE, &parts) < 0);
		part = parts;

		test_assert_idx(part->children_count == 1, i);
		test_assert_idx(part->flags == (MESSAGE_PART_FLAG_MULTIPART | MESSAGE_PART_FLAG_IS_MIME), i);
		test_assert_idx(part->header_size.lines == 3, i);
		test_assert_idx(part->header_size.physical_size == (size_t)(63 + variance), i);
		test_assert_idx(part->header_size.virtual_size == (size_t)(66 + variance), i);
		test_assert_idx(part->body_size.lines == 5, i);
		test_assert_idx(part->body_size.physical_size == 47, i);
		test_assert_idx(part->body_size.virtual_size == 52, i);
		test_assert_strcmp_idx(part->data->content_type, "multipart", i);
		test_assert_strcmp_idx(part->data->content_subtype, "mixed", i);
		part = part->children;

		test_assert_idx(part->children_count == 0, i);
		test_assert_idx(part->flags == (MESSAGE_PART_FLAG_TEXT |
						MESSAGE_PART_FLAG_IS_MIME |
						MESSAGE_PART_FLAG_OVERFLOW), i);
		test_assert_idx(part->header_size.lines == 2, i);
		test_assert_idx(part->header_size.physical_size == 26, i);
		test_assert_idx(part->header_size.virtual_size == 28, i);
		test_assert_idx(part->body_size.lines == 2, i);
		test_assert_idx(part->body_size.physical_size == 17, i);
		test_assert_strcmp_idx(part->data->content_type, "text", i);
		test_assert_strcmp_idx(part->data->content_subtype, "plain", i);

		test_parsed_parts(input, parts);
		i_stream_unref(&input);
		pool_unref(&pool);
	};

	/* test for +10MB header */
	const size_t test_hdr_size = 10*1024*1024UL;
	const size_t test_msg_size = test_hdr_size + 1024UL;
	/* add space for parser */
	pool = pool_alloconly_create("10mb header", test_msg_size + 10240UL);
	string_t *buffer = str_new(pool, test_msg_size + 1);

	str_append(buffer, "MIME-Version: ");

	/* @UNSAFE */
	char *tmp = buffer_append_space_unsafe(buffer, test_hdr_size);
	memset(tmp, 'a', test_hdr_size);

	str_append_c(buffer, '\n');
	str_append(buffer, "Content-Type: multipart/mixed; boundary=1\n\n--1--");

	input = test_istream_create_data(buffer->data, buffer->used);
	test_assert(message_parse_stream(pool, input, &parser_set, TRUE, &parts) < 0);

	i_stream_unref(&input);
	pool_unref(&pool);
	test_end();
}

static void test_message_parser_mime_version_missing(void)
{
	test_begin("message parser mime version missing");

static const char input_msg[] =
"Content-Type: multipart/mixed; boundary=\"1\"\n\n"
"--1\n"
"Content-Type: text/plain\n"
"\n"
"hello, world\n"
"--1\n";

	const struct message_parser_settings parser_set = {
		.max_total_mime_parts = 2,
		.flags = MESSAGE_PARSER_FLAG_MIME_VERSION_STRICT,
	};
	struct istream *input;
	struct message_part *parts, *part;
	pool_t pool;

	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg);

	test_assert(message_parse_stream(pool, input, &parser_set, TRUE, &parts) < 0);
	part = parts;

	/* non-MIME message should end up as plain text mail */

	test_assert(part->children_count == 0);
	test_assert(part->flags == MESSAGE_PART_FLAG_TEXT);
	test_assert(part->header_size.lines == 2);
	test_assert(part->header_size.physical_size == 45);
	test_assert(part->header_size.virtual_size == 47);
	test_assert(part->body_size.lines == 5);
	test_assert(part->body_size.physical_size == 47);
	test_assert(part->body_size.virtual_size == 52);
	test_assert(part->children == NULL);
	test_assert(part->data->content_type == NULL);
	test_assert(part->data->content_subtype == NULL);

	test_parsed_parts(input, parts);
	i_stream_unref(&input);
	pool_unref(&pool);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_parser_small_blocks,
		test_message_parser_stop_early,
		test_message_parser_truncated_mime_headers,
		test_message_parser_truncated_mime_headers2,
		test_message_parser_truncated_mime_headers3,
		test_message_parser_empty_multipart,
		test_message_parser_duplicate_mime_boundary,
		test_message_parser_garbage_suffix_mime_boundary,
		test_message_parser_trailing_dashes,
		test_message_parser_continuing_mime_boundary,
		test_message_parser_continuing_truncated_mime_boundary,
		test_message_parser_continuing_mime_boundary_reverse,
		test_message_parser_long_mime_boundary,
		test_message_parser_no_eoh,
		test_message_parser_mime_part_nested_limit,
		test_message_parser_mime_part_nested_limit_rfc822,
		test_message_parser_mime_part_limit,
		test_message_parser_mime_part_limit_rfc822,
		test_message_parser_mime_version,
		test_message_parser_mime_version_missing,
		NULL
	};
	return test_run(test_functions);
}
