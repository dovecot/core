/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strfuncs.h"
#include "unichar.h"
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
	"h4: \r\n"
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
	test_assert(hdr->name_offset == 32 && hdr->full_value_offset == 36);
	test_assert(hdr->name_len == 2 && strcmp(hdr->name, "h4") == 0);
	test_assert(hdr->middle_len == 2 && memcmp(hdr->middle, ": ", 2) == 0);
	test_assert(hdr->value_len == 0 && memcmp(hdr->value, "", 0) == 0);
	test_assert(!hdr->continues && !hdr->continued && !hdr->eoh &&
		    !hdr->no_newline && hdr->crlf_newline);
	test_assert(hdr->full_value_len == 0 && hdr->full_value != NULL);

	test_assert(message_parse_header_next(parser, &hdr) > 0);
	test_assert(hdr->name_offset == 38 && hdr->full_value_offset == 38);
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
	struct message_size hdr_size, hdr_size2;
	struct istream *input;
	bool has_nuls;

	test_begin("message header parser");
	input = test_istream_create(test1_msg);

	for (hdr_flags = 0; hdr_flags <= max_hdr_flags; hdr_flags++) {
		i_stream_seek(input, 0);
		parser = message_parse_header_init(input, &hdr_size, hdr_flags);
		test_message_header_parser_one(parser, hdr_flags);
		message_parse_header_deinit(&parser);
		i_stream_seek(input, 0);
		message_get_header_size(input, &hdr_size2, &has_nuls);
	}

	test_assert(!has_nuls);
	test_assert(hdr_size.physical_size == hdr_size2.physical_size);
	test_assert(hdr_size.virtual_size == hdr_size2.virtual_size);
	test_assert(hdr_size.lines == hdr_size2.lines);
	test_assert(hdr_size.physical_size == strlen(test1_msg)-TEST1_MSG_BODY_LEN);
	test_assert(hdr_size.virtual_size == strlen(test1_msg) - TEST1_MSG_BODY_LEN + 4);

	i_stream_unref(&input);
	test_end();
}

static void hdr_write(string_t *str, struct message_header_line *hdr)
{
	if (!hdr->continued) {
		str_append(str, hdr->name);
		if (hdr->middle_len > 0)
			str_append_data(str, hdr->middle, hdr->middle_len);
	}
	str_append_data(str, hdr->value, hdr->value_len);
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
					  struct message_size *size_r,
					  struct message_size *size_2_r)
{
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct istream *input;
	unsigned int i;
	size_t len = strlen(str);
	bool has_nuls;

	input = test_istream_create(str);
	test_istream_set_max_buffer_size(input, buffer_size);

	parser = message_parse_header_init(input, size_r, 0);
	for (i = 1; i <= len; i++) {
		test_istream_set_size(input, i);
		while (message_parse_header_next(parser, &hdr) > 0) ;
	}
	message_parse_header_deinit(&parser);
	i_stream_seek(input, 0);
	/* Buffer must be +1 for message_get_header_size as it's using
	   i_stream_read_bytes which does not work with lower buffersize
	   because it returns -2 (input buffer full) if 2 bytes are wanted. */
	test_istream_set_max_buffer_size(input, buffer_size+1);
	message_get_header_size(input, size_2_r, &has_nuls);
	i_stream_unref(&input);
}

#define NAME10 "1234567890"
#define NAME100 NAME10 NAME10 NAME10 NAME10 NAME10 \
		NAME10 NAME10 NAME10 NAME10 NAME10
#define NAME1000 NAME100 NAME100 NAME100 NAME100 NAME100 \
		 NAME100 NAME100 NAME100 NAME100 NAME100

static void test_message_header_parser_long_lines(void)
{
	static const char *lf_str = NAME10": 345\n\n";
	static const char *crlf_str = NAME10": 345\r\n\r\n";
	static const char *lf_str_vl = NAME1000": Is a long header name\n\n";
	static const char *crlf_str_vl = NAME1000": Is a long header name\r\n\r\n";
	static const char *lf_str_ol = NAME1000 \
		NAME100 ": Is a overlong header name\n\n";
	static const char *crlf_str_ol = NAME1000 \
		NAME100 ": Is a overlong header name\r\n\r\n";

	struct message_size hdr_size, hdr_size2;
	size_t i, len;

	test_begin("message header parser long lines");
	len = strlen(lf_str);
	for (i = 2; i < len; i++) {
		test_message_header_parser_long_lines_str(lf_str, i, &hdr_size, &hdr_size2);
		test_assert(hdr_size.physical_size == len);
		test_assert(hdr_size.virtual_size == len + 2);
		test_assert(hdr_size.virtual_size == hdr_size2.virtual_size);
		test_assert(hdr_size.physical_size == hdr_size2.physical_size);
	}
	len = strlen(crlf_str);
	for (i = 3; i < len; i++) {
		test_message_header_parser_long_lines_str(crlf_str, i, &hdr_size, &hdr_size2);
		test_assert(hdr_size.physical_size == len);
		test_assert(hdr_size.virtual_size == len);
		test_assert(hdr_size.virtual_size == hdr_size2.virtual_size);
		test_assert(hdr_size.physical_size == hdr_size2.physical_size);
	}

	/* increment these faster, otherwise the test is very slow */
	len = strlen(lf_str_vl);
	for (i = 3; i < len; i *= 2) {
		 test_message_header_parser_long_lines_str(lf_str_vl, i, &hdr_size, &hdr_size2);
		 test_assert(hdr_size.physical_size == len);
		 test_assert(hdr_size.virtual_size == len + 2);
		 test_assert(hdr_size.virtual_size == hdr_size2.virtual_size);
		 test_assert(hdr_size.physical_size == hdr_size2.physical_size);
	}
	len = strlen(crlf_str_vl);
	for (i = 3; i < len; i *= 2) {
		test_message_header_parser_long_lines_str(crlf_str_vl, i, &hdr_size, &hdr_size2);
		test_assert(hdr_size.physical_size == len);
		test_assert(hdr_size.virtual_size == len);
		test_assert(hdr_size.virtual_size == hdr_size2.virtual_size);
		test_assert(hdr_size.physical_size == hdr_size2.physical_size);
	}

	/* test that parsing overlength lines work so that name & middle are
	   empty. */

	struct message_header_line *hdr;
	struct message_header_parser_ctx *ctx;
	struct istream *input;

	input = test_istream_create(lf_str_ol);
	ctx = message_parse_header_init(input, NULL, 0);

	test_assert(message_parse_header_next(ctx, &hdr) > 0 &&
		    *hdr->name == '\0' && hdr->middle == uchar_empty_ptr &&
		    hdr->name_len == 0 && hdr->middle_len == 0 &&
		    hdr->value != NULL && hdr->value_len > 0);
	test_assert(message_parse_header_next(ctx, &hdr) > 0 &&
		    hdr->eoh);
	message_parse_header_deinit(&ctx);
	i_stream_unref(&input);

	input = test_istream_create(crlf_str_ol);
	ctx = message_parse_header_init(input, NULL, 0);
	test_assert(message_parse_header_next(ctx, &hdr) > 0 &&
		    *hdr->name == '\0' && hdr->middle == uchar_empty_ptr &&
		    hdr->name_len == 0 && hdr->middle_len == 0 &&
		    hdr->value != NULL && hdr->value_len > 0);
	test_assert(message_parse_header_next(ctx, &hdr) > 0 &&
		    hdr->eoh);
	message_parse_header_deinit(&ctx);
	i_stream_unref(&input);

	/* test offset parsing */
	static const char *data = "h1" NAME1000 NAME100 \
				   ": value1\r\n" \
				   "h2" NAME1000 NAME100 \
				   ": value2\r\n" \
				   "h3" NAME1000 NAME100 \
				   ": value3\r\n\r\n";
	input = test_istream_create(data);
	ctx = message_parse_header_init(input, NULL, 0);
	test_assert(message_parse_header_next(ctx, &hdr) > 0 &&
		    hdr->full_value[0] == 'h' &&
		    hdr->full_value[1] == '1' &&
		    hdr->full_value_offset == 0);
	test_assert(message_parse_header_next(ctx, &hdr) > 0 &&
		    hdr->full_value[0] == 'h' &&
		    hdr->full_value[1] == '2' &&
		    hdr->full_value_offset == 1112);
	test_assert(message_parse_header_next(ctx, &hdr) > 0 &&
		    hdr->full_value[0] == 'h' &&
		    hdr->full_value[1] == '3' &&
		    hdr->full_value_offset == 2224);
	test_assert(message_parse_header_next(ctx, &hdr) > 0 &&
		    hdr->eoh);

	message_parse_header_deinit(&ctx);
	i_stream_unref(&input);

	test_end();
}

static void test_message_header_parser_extra_cr_in_eoh(void)
{
	static const char *str = "a:b\n\r\r\n";
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct istream *input;

	test_begin("message header parser extra CR in EOH");

	input = test_istream_create(str);
	parser = message_parse_header_init(input, NULL, 0);
	test_assert(message_parse_header_next(parser, &hdr) > 0 &&
		    strcmp(hdr->name, "a") == 0);
	test_assert(message_parse_header_next(parser, &hdr) > 0 &&
		    *hdr->value == '\r' && hdr->value_len == 1 &&
		    hdr->full_value_offset == 4 &&
		    hdr->middle_len == 0 &&
		    hdr->name_len == 0 && !hdr->eoh);
	test_assert(message_parse_header_next(parser, &hdr) < 0);
	message_parse_header_deinit(&parser);
	test_assert(input->stream_errno == 0);
	i_stream_unref(&input);
	test_end();
}

static void test_message_header_parser_no_eoh(void)
{
	static const char *str = "a:b\n";
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct istream *input;

	test_begin("message header parser no EOH");

	input = test_istream_create(str);
	parser = message_parse_header_init(input, NULL, 0);
	test_assert(message_parse_header_next(parser, &hdr) > 0 &&
		    strcmp(hdr->name, "a") == 0);
	test_assert_strcmp(message_header_strdup(pool_datastack_create(),
						 hdr->value, hdr->value_len),
			   "b");
	test_assert(message_parse_header_next(parser, &hdr) < 0);
	message_parse_header_deinit(&parser);
	test_assert(input->stream_errno == 0);
	i_stream_unref(&input);
	test_end();
}

static void test_message_header_parser_nul(void)
{
	static const unsigned char str[] = "a :\0\0b\n";
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct istream *input;

	test_begin("message header parser NUL");

	input = test_istream_create_data(str, sizeof(str)-1);
	parser = message_parse_header_init(input, NULL, 0);
	test_assert(message_parse_header_next(parser, &hdr) > 0 &&
		    strcmp(hdr->name, "a") == 0);
	test_assert(hdr->value_len >= 3 && memcmp("\0\0b", hdr->value, 3) == 0);
	test_assert_strcmp(message_header_strdup(pool_datastack_create(),
						 hdr->value, hdr->value_len),
			   UNICODE_REPLACEMENT_CHAR_UTF8 UNICODE_REPLACEMENT_CHAR_UTF8"b");
	test_assert(message_parse_header_next(parser, &hdr) < 0);
	message_parse_header_deinit(&parser);
	test_assert(input->stream_errno == 0);
	i_stream_unref(&input);
	test_end();
}

static void test_message_header_parser_extra_crlf_in_name(void)
{
	static const unsigned char str[] = "X-Header\r\n  Name: Header Value\n\n";
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct istream *input;
	test_begin("message header parser CRLF in header name");

	input = test_istream_create_data(str, sizeof(str)-1);
	parser = message_parse_header_init(input, NULL, 0);
	hdr = NULL;
	test_assert(message_parse_header_next(parser, &hdr) > 0 &&
		    *hdr->name == '\0' && hdr->middle == uchar_empty_ptr &&
		    hdr->name_len == 0 && hdr->middle_len == 0 &&
		    hdr->value != NULL && hdr->value_len > 0);
	test_assert(message_parse_header_next(parser, &hdr) > 0 &&
		    *hdr->name == '\0' && hdr->middle == uchar_empty_ptr &&
		    hdr->name_len == 0 && hdr->middle_len == 0 &&
		    hdr->value != NULL && hdr->value_len > 0 &&
		    hdr->continued);
	test_assert(message_parse_header_next(parser, &hdr) > 0 &&
		    hdr->eoh);

	message_parse_header_deinit(&parser);
	i_stream_unref(&input);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_header_parser,
		test_message_header_parser_partial,
		test_message_header_parser_long_lines,
		test_message_header_parser_extra_cr_in_eoh,
		test_message_header_parser_no_eoh,
		test_message_header_parser_nul,
		test_message_header_parser_extra_crlf_in_name,
		NULL
	};
	return test_run(test_functions);
}
