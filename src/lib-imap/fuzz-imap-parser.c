/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "istream.h"
#include "fuzzer.h"
#include "imap-parser.h"

#define MAX_LINE_SIZE 4096

FUZZ_BEGIN_DATA(const uint8_t *data, size_t size)
{
	struct istream *input = i_stream_create_from_data(data, size);
	struct imap_parser *parser =
		imap_parser_create(input, NULL, MAX_LINE_SIZE, NULL);
	const struct imap_arg *args;
	const char *tag, *name;

	(void)i_stream_read(input);

	if (imap_parser_read_tag(parser, &tag) > 0 &&
	    imap_parser_read_command_name(parser, &name) > 0)
		(void)imap_parser_finish_line(parser, 0, 0, &args);

	imap_parser_unref(&parser);
	i_stream_destroy(&input);
}
FUZZ_END
