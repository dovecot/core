/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

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
	enum imap_parser_error parse_error;

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
	test_assert(strcmp(imap_parser_get_error
		(parser, &parse_error), "CR sent without LF") == 0 &&
		parse_error == IMAP_PARSE_ERROR_BAD_SYNTAX);

	imap_parser_unref(&parser);
	i_stream_destroy(&input);
	test_end();
}

static void test_imap_parser_partial_list(void)
{
	static const char *test_input = "((((foo {1000000}\r\n";
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args, *sub_list;

	test_begin("imap parser partial list");
	input = test_istream_create(test_input);
	parser = imap_parser_create(input, NULL, 1024);

	(void)i_stream_read(input);
	test_assert(imap_parser_read_args(parser, 0,
		IMAP_PARSE_FLAG_LITERAL_SIZE, &args) == 1);
	for (unsigned int i = 0; i < 4; i++) {
		sub_list = imap_arg_as_list(&args[0]);
		test_assert(IMAP_ARG_IS_EOL(&args[1]));
		args = sub_list;
	}
	test_assert(imap_arg_atom_equals(&args[0], "foo"));
	test_assert(args[1].type == IMAP_ARG_LITERAL_SIZE);
	test_assert(IMAP_ARG_IS_EOL(&args[2]));

	imap_parser_unref(&parser);
	i_stream_destroy(&input);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_parser_crlf,
		test_imap_parser_partial_list,
		NULL
	};
	return test_run(test_functions);
}
