/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "message-size.h"
#include "message-header-parser.h"
#include "test-common.h"

#define TEST1_MSG_BODY_LEN 5
static const char *test1_msg =
	"h1:  v1\n"
	"h2:\n"
	" v2\r\n"
	"h3: \r\n"
	"\tv3\n"
	"\tw3\r\n"
	"\n"
	" body";

static void
test_message_header_parser_one(struct message_header_parser_ctx *parser,
			       enum message_header_parser_flags hdr_flags)
{
	struct message_header_line *hdr;
	bool use_full_value;

	use_full_value = hdr_flags != 0;

	test_assert(message_parse_header_next(parser, &hdr) > 0);
	test_assert(hdr->name_offset == 0);
	if ((hdr_flags & MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP) == 0)
		test_assert(hdr->full_value_offset == 4);
	else
		test_assert(hdr->full_value_offset == 5);
	test_assert(hdr->name_len == 2 && strcmp(hdr->name, "h1") == 0);
	if ((hdr_flags & MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP) == 0) {
		test_assert(hdr->middle_len == 2 && memcmp(hdr->middle, ": ", 2) == 0);
		test_assert(hdr->value_len == 3 && memcmp(hdr->value, " v1", 3) == 0);
	} else {
		test_assert(hdr->middle_len == 3 && memcmp(hdr->middle, ":  ", 3) == 0);
		test_assert(hdr->value_len == 2 && memcmp(hdr->value, "v1", 2) == 0);
	}
	test_assert(!hdr->continues && !hdr->continued && !hdr->eoh &&
		    !hdr->no_newline && !hdr->crlf_newline);

	test_assert(message_parse_header_next(parser, &hdr) > 0);
	test_assert(hdr->name_offset == 8 && hdr->full_value_offset == 11);
	test_assert(hdr->name_len == 2 && strcmp(hdr->name, "h2") == 0);
	test_assert(hdr->middle_len == 1 && memcmp(hdr->middle, ":", 1) == 0);
	test_assert(hdr->value_len == 0);
	test_assert(hdr->continues && !hdr->continued && !hdr->eoh &&
		    !hdr->no_newline && !hdr->crlf_newline);
	if (use_full_value) hdr->use_full_value = TRUE;

	test_assert(message_parse_header_next(parser, &hdr) > 0);
	test_assert(hdr->name_offset == 8 && hdr->full_value_offset == 11);
	test_assert(hdr->name_len == 2 && strcmp(hdr->name, "h2") == 0);
	test_assert(hdr->middle_len == 1 && memcmp(hdr->middle, ":", 1) == 0);
	test_assert(hdr->value_len == 3 && memcmp(hdr->value, " v2", 3) == 0);
	test_assert(!hdr->continues && hdr->continued && !hdr->eoh &&
		    !hdr->no_newline && hdr->crlf_newline);
	if ((hdr_flags & MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE) != 0) {
		test_assert(hdr->full_value_len == 3 &&
			    memcmp(hdr->full_value, " v2", 3) == 0);
	} else if (use_full_value) {
		test_assert(hdr->full_value_len == 4 &&
			    memcmp(hdr->full_value, "\n v2", 4) == 0);
	}

	test_assert(message_parse_header_next(parser, &hdr) > 0);
	test_assert(hdr->name_offset == 17 && hdr->full_value_offset == 21);
	test_assert(hdr->name_len == 2 && strcmp(hdr->name, "h3") == 0);
	test_assert(hdr->middle_len == 2 && memcmp(hdr->middle, ": ", 2) == 0);
	test_assert(hdr->value_len == 0);
	test_assert(hdr->continues && !hdr->continued && !hdr->eoh &&
		    !hdr->no_newline && hdr->crlf_newline);
	if (use_full_value) hdr->use_full_value = TRUE;

	test_assert(message_parse_header_next(parser, &hdr) > 0);
	test_assert(hdr->name_offset == 17 && hdr->full_value_offset == 21);
	test_assert(hdr->name_len == 2 && strcmp(hdr->name, "h3") == 0);
	test_assert(hdr->middle_len == 2 && memcmp(hdr->middle, ": ", 2) == 0);
	test_assert(hdr->value_len == 3 && memcmp(hdr->value, "\tv3", 3) == 0);
	test_assert(hdr->continues && hdr->continued && !hdr->eoh &&
		    !hdr->no_newline && !hdr->crlf_newline);
	if (use_full_value) hdr->use_full_value = TRUE;
	if ((hdr_flags & MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE) != 0) {
		test_assert(hdr->full_value_len == 3 &&
			    memcmp(hdr->full_value, " v3", 3) == 0);
	} else if ((hdr_flags & MESSAGE_HEADER_PARSER_FLAG_DROP_CR) != 0) {
		test_assert(hdr->full_value_len == 4 &&
			    memcmp(hdr->full_value, "\n\tv3", 4) == 0);
	} else if (use_full_value) {
		test_assert(hdr->full_value_len == 5 &&
			    memcmp(hdr->full_value, "\r\n\tv3", 5) == 0);
	}

	test_assert(message_parse_header_next(parser, &hdr) > 0);
	test_assert(hdr->name_offset == 17 && hdr->full_value_offset == 21);
	test_assert(hdr->name_len == 2 && strcmp(hdr->name, "h3") == 0);
	test_assert(hdr->middle_len == 2 && memcmp(hdr->middle, ": ", 2) == 0);
	test_assert(hdr->value_len == 3 && memcmp(hdr->value, "\tw3", 3) == 0);
	test_assert(!hdr->continues && hdr->continued && !hdr->eoh &&
		    !hdr->no_newline && hdr->crlf_newline);
	if ((hdr_flags & MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE) != 0) {
		test_assert(hdr->full_value_len == 6 &&
			    memcmp(hdr->full_value, " v3 w3", 6) == 0);
	} else if ((hdr_flags & MESSAGE_HEADER_PARSER_FLAG_DROP_CR) != 0) {
		test_assert(hdr->full_value_len == 8 &&
			    memcmp(hdr->full_value, "\n\tv3\n\tw3", 8) == 0);
	} else if (use_full_value) {
		test_assert(hdr->full_value_len == 9 &&
			    memcmp(hdr->full_value, "\r\n\tv3\n\tw3", 9) == 0);
	}

	test_assert(message_parse_header_next(parser, &hdr) > 0);
	test_assert(hdr->name_offset == 32 && hdr->full_value_offset == 32);
	test_assert(hdr->name_len == 0 && hdr->middle_len == 0 && hdr->value_len == 0);
	test_assert(!hdr->continues && !hdr->continued && hdr->eoh &&
		    !hdr->no_newline && !hdr->crlf_newline);

	test_assert(message_parse_header_next(parser, &hdr) < 0);
}

static void test_message_header_parser(void)
{
	static enum message_header_parser_flags max_hdr_flags =
		MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP |
		MESSAGE_HEADER_PARSER_FLAG_DROP_CR |
		MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE;
	enum message_header_parser_flags hdr_flags;
	struct message_header_parser_ctx *parser;
	struct message_size hdr_size;
	struct istream *input;

	test_begin("message header parser");
	input = test_istream_create(test1_msg);

	for (hdr_flags = 0; hdr_flags <= max_hdr_flags; hdr_flags++) {
		i_stream_seek(input, 0);
		parser = message_parse_header_init(input, &hdr_size, hdr_flags);
		test_message_header_parser_one(parser, hdr_flags);
		message_parse_header_deinit(&parser);
	}
	test_assert(hdr_size.physical_size == strlen(test1_msg)-TEST1_MSG_BODY_LEN);
	test_assert(hdr_size.virtual_size == strlen(test1_msg) - TEST1_MSG_BODY_LEN + 4);

	i_stream_unref(&input);
	test_end();
}

static void hdr_write(string_t *str, struct message_header_line *hdr)
{
	if (!hdr->continued) {
		str_append(str, hdr->name);
		str_append_n(str, hdr->middle, hdr->middle_len);
	}
	str_append_n(str, hdr->value, hdr->value_len);
	if (!hdr->no_newline) {
		if (hdr->crlf_newline)
			str_append_c(str, '\r');
		str_append_c(str, '\n');
	}
}

static void test_message_header_parser_partial(void)
{
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct istream *input;
	unsigned int i, max = (strlen(test1_msg)-TEST1_MSG_BODY_LEN)*2;
	string_t *str;
	int ret;

	test_begin("message header parser partial");
	input = test_istream_create(test1_msg);
	test_istream_set_allow_eof(input, FALSE);

	str = t_str_new(max);
	parser = message_parse_header_init(input, NULL, 0);
	for (i = 0; i <= max; i++) {
		test_istream_set_size(input, i/2);
		while ((ret = message_parse_header_next(parser, &hdr)) > 0)
			hdr_write(str, hdr);
		test_assert((ret == 0 && i < max) ||
			    (ret < 0 && i == max));
	}
	message_parse_header_deinit(&parser);

	str_append(str, " body");
	test_assert(strcmp(str_c(str), test1_msg) == 0);
	i_stream_unref(&input);
	test_end();
}

static void
test_message_header_parser_long_lines_str(const char *str,
					  unsigned int buffer_size,
					  struct message_size *size_r)
{
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct istream *input;
	unsigned int i, len = strlen(str);

	input = test_istream_create(str);
	test_istream_set_max_buffer_size(input, buffer_size);

	parser = message_parse_header_init(input, size_r, 0);
	for (i = 1; i <= len; i++) {
		test_istream_set_size(input, i);
		while (message_parse_header_next(parser, &hdr) > 0) ;
	}
	message_parse_header_deinit(&parser);
	i_stream_unref(&input);
}

static void test_message_header_parser_long_lines(void)
{
	static const char *lf_str = "1234567890: 345\n\n";
	static const char *crlf_str = "1234567890: 345\r\n\r\n";
	struct message_size hdr_size;
	unsigned int i, len;

	test_begin("message header parser long lines");
	len = strlen(lf_str);
	for (i = 2; i < len; i++) {
		test_message_header_parser_long_lines_str(lf_str, i, &hdr_size);
		test_assert(hdr_size.physical_size == len);
		test_assert(hdr_size.virtual_size == len + 2);
	}
	len = strlen(crlf_str);
	for (i = 2; i < len; i++) {
		test_message_header_parser_long_lines_str(crlf_str, i, &hdr_size);
		test_assert(hdr_size.physical_size == len);
		test_assert(hdr_size.virtual_size == len);
	}
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_header_parser,
		test_message_header_parser_partial,
		test_message_header_parser_long_lines,
		NULL
	};
	return test_run(test_functions);
}
