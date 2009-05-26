/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
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

		if (p1->children) {
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

static void test_message_parser(void)
{
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_part *parts, *parts2;
	struct message_block block;
	unsigned int i;
	bool success = TRUE;
	pool_t pool;
	int ret;

	pool = pool_alloconly_create("message parser", 10240);
	input = i_stream_create_from_data(test_msg, TEST_MSG_LEN);

	parser = message_parser_init(pool, input, 0, 0);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) ;
	i_assert(ret < 0);
	ret = message_parser_deinit(&parser, &parts);
	i_assert(ret == 0);
	i_stream_unref(&input);

	input = test_istream_create(test_msg);
	test_istream_set_allow_eof(input, FALSE);

	parser = message_parser_init(pool, input, 0, 0);
	for (i = 1; i <= TEST_MSG_LEN*2+1; i++) {
		test_istream_set_size(input, i/2);
		if (i > TEST_MSG_LEN*2)
			test_istream_set_allow_eof(input, TRUE);
		while ((ret = message_parser_parse_next_block(parser,
							      &block)) > 0) ;
		if (ret < 0 && i < TEST_MSG_LEN*2) {
			success = FALSE;
			break;
		}
	}
	ret = message_parser_deinit(&parser, &parts2);
	i_assert(ret == 0);
	i_stream_unref(&input);

	if (!msg_parts_cmp(parts, parts2))
		success = FALSE;

	pool_unref(&pool);
	test_out("message_parser()", success);
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_parser,
		NULL
	};
	return test_run(test_functions);
}
