/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "imap-parser.h"
#include "test-common.h"

static void test_imap_parser_crlf(void)
{
	static const char *test_input = "foo\r\nx\ry\n";
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	unsigned int i;
	bool fatal;

	test_begin("imap parser crlf handling");
	input = test_istream_create(test_input);
	parser = imap_parser_create(input, NULL, 1024);

	/* must return -2 until LF is read */
	for (i = 0; test_input[i] != '\n'; i++) {
		test_istream_set_size(input, i+1);
		(void)i_stream_read(input);
		test_assert(imap_parser_read_args(parser, 0, 0, &args) == -2);
	}
	test_istream_set_size(input, i+1);
	(void)i_stream_read(input);
	test_assert(imap_parser_read_args(parser, 0, 0, &args) == 1);
	test_assert(args[0].type == IMAP_ARG_ATOM);
	test_assert(args[1].type == IMAP_ARG_EOL);

	/* CR without LF should fail with error */
	imap_parser_reset(parser);
	i_stream_seek(input, ++i);
	test_istream_set_size(input, ++i);
	(void)i_stream_read(input);
	test_assert(imap_parser_read_args(parser, 0, 0, &args) == -2);
	test_istream_set_size(input, ++i);
	(void)i_stream_read(input);
	test_assert(imap_parser_read_args(parser, 0, 0, &args) == -2);
	test_istream_set_size(input, ++i);
	(void)i_stream_read(input);
	test_assert(imap_parser_read_args(parser, 0, 0, &args) == -1);
	test_assert(strcmp(imap_parser_get_error(parser, &fatal), "CR sent without LF") == 0 && !fatal);

	imap_parser_destroy(&parser);
	i_stream_destroy(&input);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_parser_crlf,
		NULL
	};
	return test_run(test_functions);
}
