/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "istream.h"
#include "test-common.h"
#include "fuzzer.h"
#include "imap-parser.h"

#define MAX_LINE_SIZE 4096
#define MAX_LIST_COUNT 128

/* Number of leading bytes that configure the parser instead of being parsed. */
#define FUZZ_HEADER_SIZE 3

enum fuzz_parser_mode {
	/* Server side: "<tag> <command> <args>" */
	FUZZ_PARSER_MODE_COMMAND = 0,
	/* Client side: the tag can also be "*" or "+" */
	FUZZ_PARSER_MODE_CLIENT_TAG,
	/* Arguments only, without any tag */
	FUZZ_PARSER_MODE_ARGS,

	FUZZ_PARSER_MODE_COUNT
};

static unsigned int fuzz_parser_mode_prefix_count(enum fuzz_parser_mode mode)
{
	switch (mode) {
	case FUZZ_PARSER_MODE_COMMAND:
		return 2;
	case FUZZ_PARSER_MODE_CLIENT_TAG:
		return 1;
	case FUZZ_PARSER_MODE_ARGS:
		return 0;
	case FUZZ_PARSER_MODE_COUNT:
		break;
	}
	i_unreached();
}

/* Read the atoms preceding the arguments. Returns 1 if they were all read,
   0 if more input is needed and -1 on error. */
static int
fuzz_read_prefix(struct imap_parser *parser, enum fuzz_parser_mode mode,
		 unsigned int *prefix_left)
{
	const char *str;
	int ret;

	while (*prefix_left > 0) {
		if (mode == FUZZ_PARSER_MODE_CLIENT_TAG)
			ret = imap_parser_client_read_tag(parser, &str);
		else if (*prefix_left > 1)
			ret = imap_parser_read_tag(parser, &str);
		else
			ret = imap_parser_read_command_name(parser, &str);
		if (ret <= 0)
			return ret;
		*prefix_left -= 1;
	}
	return 1;
}

/* With IMAP_PARSE_FLAG_LITERAL_SIZE the parsing stops at each literal and
   only its size is returned. Let the parser read the literal itself, the
   same way as e.g. the APPEND command does for small enough literals.
   Returns TRUE if the parsing should be continued. */
static bool fuzz_read_literal(struct imap_parser *parser)
{
	uoff_t literal_size;

	if (!imap_parser_get_literal_size(parser, &literal_size))
		return FALSE;
	if (literal_size > MAX_LINE_SIZE)
		return FALSE;
	imap_parser_read_last_literal(parser);
	return TRUE;
}

/* Feed the input in chunks, so that also the code paths resuming the parsing
   after "more data is needed" get exercised. Returns 0 if the line can still
   be finished, -1 if the parsing already failed. */
static int
fuzz_parse_chunks(struct imap_parser *parser, struct istream *input,
		  size_t size, unsigned int chunk_size,
		  enum imap_parser_flags flags, enum fuzz_parser_mode mode)
{
	const struct imap_arg *args;
	unsigned int prefix_left = fuzz_parser_mode_prefix_count(mode);
	uoff_t offset;
	int ret;

	for (offset = 0;;) {
		offset = I_MIN(offset + chunk_size, size);
		if (offset == size)
			test_istream_set_allow_eof(input, TRUE);
		test_istream_set_size(input, offset);
		(void)i_stream_read(input);

		ret = fuzz_read_prefix(parser, mode, &prefix_left);
		if (ret < 0)
			return -1;
		if (ret > 0) {
			ret = imap_parser_read_args(parser, 0, flags, &args);
			if (ret == -1)
				return -1;
			if (ret >= 0 && !fuzz_read_literal(parser))
				return 0;
		}
		if (offset == size)
			return 0;
	}
}

static void fuzz_imap_parser(const unsigned char *data, size_t size)
{
	struct imap_parser_params params = {
		.list_count_limit = MAX_LIST_COUNT,
	};
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	enum imap_parser_flags flags;
	enum fuzz_parser_mode mode;
	unsigned int chunk_size;
	bool literal_minus;

	if (size < FUZZ_HEADER_SIZE)
		return;

	/* data[0] and the lowest bit of data[1] are the parser flags, the
	   next bit of data[1] enables LITERAL- and the two bits above it
	   select what the input is parsed as. data[2] is the size of the
	   chunks the input is fed in. */
	flags = data[0] | ((data[1] & 0x01) << 8);
	literal_minus = (data[1] & 0x02) != 0;
	mode = ((data[1] >> 2) & 0x03) % FUZZ_PARSER_MODE_COUNT;
	chunk_size = (unsigned int)data[2] + 1;
	data += FUZZ_HEADER_SIZE;
	size -= FUZZ_HEADER_SIZE;

	input = test_istream_create_data(data, size);
	test_istream_set_allow_eof(input, FALSE);
	parser = imap_parser_create(input, NULL, MAX_LINE_SIZE, &params);
	if (literal_minus)
		imap_parser_enable_literal_minus(parser);

	if (fuzz_parse_chunks(parser, input, size, chunk_size, flags, mode) == 0)
		(void)imap_parser_finish_line(parser, 0, flags, &args);

	imap_parser_unref(&parser);
	i_stream_unref(&input);
}

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	fuzz_imap_parser(data, size);
}
FUZZ_END
