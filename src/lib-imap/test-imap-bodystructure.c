/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "message-parser.h"
#include "imap-bodystructure.h"
#include "test-common.h"

static const char testmsg[] =
"From: user@domain.org\n"
"Date: Sat, 24 Mar 2007 23:00:00 +0200\n"
"Mime-Version: 1.0\n"
"Content-Type: multipart/mixed; boundary=\"foo\n"
" bar\"\n"
"\n"
"Root MIME prologue\n"
"\n"
"--foo bar\n"
"Content-Type: text/x-myown; charset=us-ascii; foo=\"quoted\\\"string\"\n"
"Content-ID: <foo@example.com>\n"
"Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==\n"
"Content-Disposition: inline; foo=bar\n"
"Content-Description: hellodescription\n"
"Content-Language: en, fi, se\n"
"Content-Location: http://example.com/test.txt\n"
"\n"
"hello\n"
"\n"
"--foo bar\n"
"Content-Type: message/rfc822\n"
"\n"
"From: sub@domain.org\n"
"Date: Sun, 12 Aug 2012 12:34:56 +0300\n"
"Subject: submsg\n"
"Content-Type: multipart/alternative; boundary=\"sub1\"\n"
"\n"
"Sub MIME prologue\n"
"--sub1\n"
"Content-Type: text/html\n"
"Content-Transfer-Encoding: 8bit\n"
"\n"
"<p>Hello world</p>\n"
"\n"
"--sub1\n"
"Content-Type: text/plain\n"
"\n"
"Hello another world\n"
"\n"
"--sub1--\n"
"Sub MIME epilogue\n"
"\n"
"--foo bar--\n"
"Root MIME epilogue\n";

static const char testmsg_bodystructure[] =
"(\"text\" \"x-myown\" (\"charset\" \"us-ascii\" \"foo\" \"quoted\\\"string\") \"<foo@example.com>\" \"hellodescription\" \"7bit\" 7 1 \"Q2hlY2sgSW50ZWdyaXR5IQ==\" (\"inline\" (\"foo\" \"bar\")) (\"en\" \"fi\" \"se\") \"http://example.com/test.txt\")(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 331 (\"Sun, 12 Aug 2012 12:34:56 +0300\" \"submsg\" ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub\" \"domain.org\")) NIL NIL NIL NIL NIL) ((\"text\" \"html\" (\"charset\" \"us-ascii\") NIL NIL \"8bit\" 20 1 NIL NIL NIL NIL)(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 21 1 NIL NIL NIL NIL) \"alternative\" (\"boundary\" \"sub1\") NIL NIL NIL) 19 NIL NIL NIL NIL) \"mixed\" (\"boundary\" \"foo bar\") NIL NIL NIL";

static const char testmsg_body[] =
"(\"text\" \"x-myown\" (\"charset\" \"us-ascii\" \"foo\" \"quoted\\\"string\") \"<foo@example.com>\" \"hellodescription\" \"7bit\" 7 1)(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 331 (\"Sun, 12 Aug 2012 12:34:56 +0300\" \"submsg\" ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub\" \"domain.org\")) ((NIL NIL \"sub\" \"domain.org\")) NIL NIL NIL NIL NIL) ((\"text\" \"html\" (\"charset\" \"us-ascii\") NIL NIL \"8bit\" 20 1)(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 21 1) \"alternative\") 19) \"mixed\"";

static struct message_part *msg_parse(pool_t pool, bool parse_bodystructure)
{
	struct message_parser_ctx *parser;
	struct istream *input;
	struct message_block block;
	struct message_part *parts;
	int ret;

	input = i_stream_create_from_data(testmsg, sizeof(testmsg)-1);
	parser = message_parser_init(pool, input,
			MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP |
			MESSAGE_HEADER_PARSER_FLAG_DROP_CR,
			MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0) {
		if (parse_bodystructure) {
			imap_bodystructure_parse_header(pool, block.part,
							block.hdr);
		}
	}
	test_assert(ret < 0);

	test_assert(message_parser_deinit(&parser, &parts) == 0);
	i_stream_unref(&input);
	return parts;
}

static void test_imap_bodystructure_write(void)
{
	struct message_part *parts;
	string_t *str = t_str_new(128);
	pool_t pool = pool_alloconly_create("imap bodystructure write", 1024);

	test_begin("imap bodystructure write");
	parts = msg_parse(pool, TRUE);

	imap_bodystructure_write(parts, str, TRUE);
	test_assert(strcmp(str_c(str), testmsg_bodystructure) == 0);

	str_truncate(str, 0);
	imap_bodystructure_write(parts, str, FALSE);
	test_assert(strcmp(str_c(str), testmsg_body) == 0);

	pool_unref(&pool);
	test_end();
}

static void test_imap_bodystructure_parse(void)
{
	struct message_part *parts;
	const char *error;
	string_t *str = t_str_new(128);
	pool_t pool = pool_alloconly_create("imap bodystructure parse", 1024);

	test_begin("imap bodystructure parser");
	parts = msg_parse(pool, FALSE);

	test_assert(imap_body_parse_from_bodystructure(testmsg_bodystructure,
						       str, &error) == 0);
	test_assert(strcmp(str_c(str), testmsg_body) == 0);

	test_assert(imap_bodystructure_parse(testmsg_bodystructure,
					     pool, parts, &error) == 0);

	str_truncate(str, 0);
	imap_bodystructure_write(parts, str, TRUE);
	test_assert(strcmp(str_c(str), testmsg_bodystructure) == 0);

	pool_unref(&pool);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_bodystructure_write,
		test_imap_bodystructure_parse,
		NULL
	};
	return test_run(test_functions);
}
