/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "charset-utf8.h"
#include "message-parser.h"
#include "message-header-decode.h"
#include "message-decoder.h"
#include "message-part-data.h"
#include "test-common.h"

void message_header_decode_utf8(const unsigned char *data, size_t size,
				buffer_t *dest,
				normalizer_func_t *normalizer ATTR_UNUSED)
{
	buffer_append(dest, data, size);
}

static void test_message_decoder(void)
{
	struct message_decoder_context *ctx;
	struct message_part part;
	struct message_header_line hdr;
	struct message_block input, output;

	test_begin("message decoder");

	i_zero(&part);
	i_zero(&input);
	memset(&output, 0xff, sizeof(output));
	input.part = &part;

	ctx = message_decoder_init(NULL, 0);

	i_zero(&hdr);
	hdr.name = "Content-Transfer-Encoding";
	hdr.name_len = strlen(hdr.name);
	hdr.full_value = (const void *)"quoted-printable";
	hdr.full_value_len = strlen((const char *)hdr.full_value);
	input.hdr = &hdr;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(output.size == 0);

	input.hdr = NULL;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));

	input.hdr = NULL;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));

	input.data = (const void *)"foo           ";
	input.size = strlen((const char *)input.data);
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(output.size == 3);
	test_assert(memcmp(output.data, "foo", 3) == 0);

	input.data = (const void *)"bar";
	input.size = strlen((const char *)input.data);
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(output.size == 14);
	test_assert(memcmp(output.data, "           bar", 14) == 0);

	/* partial text - \xC3\xA4 in quoted-printable. we should get a single
	   UTF-8 letter as result */
	input.data = (const void *)"="; input.size = 1;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(output.size == 0);
	input.data = (const void *)"C"; input.size = 1;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(output.size == 0);
	input.data = (const void *)"3"; input.size = 1;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(output.size == 0);
	input.data = (const void *)"=A"; input.size = 2;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(output.size == 0);
	input.data = (const void *)"4"; input.size = 1;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(output.size == 2);
	test_assert(memcmp(output.data, "\xC3\xA4", 2) == 0);

	message_decoder_deinit(&ctx);

	test_end();
}

static void test_message_decoder_multipart(void)
{
	static const char test_message_input[] =
		"Content-Type: multipart/mixed; boundary=foo\n"
		"\n"
		"--foo\n"
		"Content-Transfer-Encoding: quoted-printable\n"
		"Content-Type: text/plain; charset=utf-8\n"
		"\n"
		"p=C3=A4iv=C3=A4=C3=A4\n"
		"\n"
		"--foo\n"
		"Content-Transfer-Encoding: base64\n"
		"Content-Type: text/plain; charset=utf-8\n"
		"\n"
		"ecO2dMOkIHZhYW4uCg== ignored\n"
		"--foo\n"
		"Content-Transfer-Encoding: base64\n"
		"Content-Type: text/plain; charset=utf-8\n"
		"\n"
		"?garbage\n"
		"--foo--\n";
	const struct message_parser_settings parser_set = { .flags = 0, };
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_part *parts;
	struct message_block input, output;
	struct istream *istream;
	string_t *str_out = t_str_new(20);
	int ret;

	test_begin("message decoder multipart");

	istream = test_istream_create(test_message_input);
	parser = message_parser_init(pool_datastack_create(), istream, &parser_set);
	decoder = message_decoder_init(NULL, 0);

	test_istream_set_allow_eof(istream, FALSE);
	for (size_t i = 0; i < sizeof(test_message_input); i++) {
		if (i == sizeof(test_message_input)-1)
			test_istream_set_allow_eof(istream, TRUE);
		test_istream_set_size(istream, i);
		while ((ret = message_parser_parse_next_block(parser, &input)) > 0) {
			if (message_decoder_decode_next_block(decoder, &input, &output) &&
			    output.hdr == NULL && output.size > 0)
				str_append_data(str_out, output.data, output.size);
		}
		if (i == sizeof(test_message_input)-1)
			test_assert(ret == -1);
		else
			test_assert(ret == 0);
	}
	/* NOTE: qp-decoder decoder changes \n into \r\n */
	test_assert_strcmp(str_c(str_out), "p\xC3\xA4iv\xC3\xA4\xC3\xA4\r\ny\xC3\xB6t\xC3\xA4 vaan.\n");

	message_decoder_deinit(&decoder);
	message_parser_deinit(&parser, &parts);
	test_assert(istream->stream_errno == 0);
	i_stream_unref(&istream);
	test_end();
}

static void test_message_decoder_current_content_type(void)
{
	struct message_decoder_context *ctx;
	struct message_part part, part2, part3;
	struct message_header_line hdr;
	struct message_block input, output;

	test_begin("message_decoder_current_content_type()");

	i_zero(&part);
	part2 = part3 = part;

	i_zero(&input);
	memset(&output, 0xff, sizeof(output));
	input.part = &part;

	ctx = message_decoder_init(NULL, 0);
	test_assert(message_decoder_current_content_type(ctx) == NULL);

	/* multipart/mixed */
	i_zero(&hdr);
	hdr.name = "Content-Type";
	hdr.name_len = strlen(hdr.name);
	hdr.full_value = (const void *)"multipart/mixed; boundary=x";
	hdr.full_value_len = strlen((const char *)hdr.full_value);
	input.hdr = &hdr;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));

	input.hdr = NULL;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(strcmp(message_decoder_current_content_type(ctx), "multipart/mixed") == 0);

	/* child 1 */
	input.part = &part2;
	hdr.full_value = (const void *)"text/plain";
	hdr.full_value_len = strlen((const char *)hdr.full_value);
	input.hdr = &hdr;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));

	input.hdr = NULL;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(strcmp(message_decoder_current_content_type(ctx), "text/plain") == 0);

	/* child 2 */
	input.part = &part3;
	hdr.full_value = (const void *)"application/pdf";
	hdr.full_value_len = strlen((const char *)hdr.full_value);
	input.hdr = &hdr;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));

	input.hdr = NULL;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));
	test_assert(strcmp(message_decoder_current_content_type(ctx), "application/pdf") == 0);

	/* reset */
	message_decoder_decode_reset(ctx);
	test_assert(message_decoder_current_content_type(ctx) == NULL);

	message_decoder_deinit(&ctx);

	test_end();
}

static void test_message_decoder_content_transfer_encoding(void)
{
	static const unsigned char test_message_input[] =
"Content-Type: multipart/mixed; boundary=\"1\"\n"
"MIME-Version: 1.0\n\n"
"--1\n"
"Content-Transfer-Encoding:      7bit\n"
"Content-Type: text/plain; charset=us-ascii\n\n"
"Move black king to queen's bishop\n\n"
"--1\n"
"Content-Transfer-Encoding:\t\t\t\tbinary\n"
"Content-Type: text/plain; charset=UTF-8\n\n"
"Move \xE2\x99\x9A to \xE2\x99\x9B's \xE2\x99\x9D\n\n"
"--1\n"
"Content-Transfer-Encoding: 8bit\t\t\t\r\n"
"Content-Type: text/plain; charset=UTF-8\n\n"
"Move \xE2\x99\x9A to \xE2\x99\x9B's \xE2\x99\x9D\n\n"
"--1\n"
"Content-Transfer-Encoding: quoted-printable              \r\n"
"Content-Type: text/plain; charset=UTF-8\n\n"
"Move =E2=99=9A to =E2=99=9B's =E2=99=9D\n\n"
"--1\n"
"Content-Transfer-Encoding: base64\n"
"Content-Type: text/plain; charset=UTF-8\n\n"
"TW92ZSDimZogdG8g4pmbJ3Mg4pmdCg==\n\n"
"--1--\n";

	static const char test_message_output[] =
"Move black king to queen's bishop\n"
"Move \xE2\x99\x9A to \xE2\x99\x9B's \xE2\x99\x9D\n"
"Move \xE2\x99\x9A to \xE2\x99\x9B's \xE2\x99\x9D\n"
"Move \xE2\x99\x9A to \xE2\x99\x9B's \xE2\x99\x9D\r\n"
"Move \xE2\x99\x9A to \xE2\x99\x9B's \xE2\x99\x9D\n";

	test_begin("message decoder content transfer encoding");

	const struct message_parser_settings parser_set = { .flags = 0, };
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_part *parts, *part;
	struct message_block input, output;
	struct istream *istream;
	string_t *str_out = t_str_new(20);
	int ret;

	pool_t pool = pool_alloconly_create("message parser", 10240);
	istream = test_istream_create_data(test_message_input,
					   sizeof(test_message_input)-1);
	parser = message_parser_init(pool, istream, &parser_set);
	decoder = message_decoder_init(NULL, 0);

	while ((ret = message_parser_parse_next_block(parser, &input)) > 0) {
		message_part_data_parse_from_header(pool, input.part, input.hdr);
		if (message_decoder_decode_next_block(decoder, &input, &output) &&
		    output.hdr == NULL && output.size > 0)
			str_append_data(str_out, output.data, output.size);
	}

	test_assert_strcmp(test_message_output, str_c(str_out));
	message_decoder_deinit(&decoder);
	message_parser_deinit(&parser, &parts);
	test_assert(istream->stream_errno == 0);

	/* validate parts */

	part = parts;
	test_assert(part->children_count == 5);
	part = part->children;
	test_assert_strcmp(part->data->content_type, "text");
	test_assert_strcmp(part->data->content_subtype, "plain");
	test_assert_strcmp(part->data->content_transfer_encoding, "7bit");
	test_assert_strcmp(part->data->content_type, "text");

	part = part->next;
	test_assert_strcmp(part->data->content_transfer_encoding, "binary");
	test_assert_strcmp(part->data->content_type, "text");
	test_assert_strcmp(part->data->content_subtype, "plain");
	part = part->next;
	test_assert_strcmp(part->data->content_transfer_encoding, "8bit");
	part = part->next;
	test_assert_strcmp(part->data->content_transfer_encoding, "quoted-printable");
	part = part->next;
	test_assert_strcmp(part->data->content_transfer_encoding, "base64");
	i_stream_unref(&istream);
	pool_unref(&pool);
	test_end();
}

static void test_message_decoder_invalid_content_transfer_encoding(void)
{
	static const unsigned char test_message_input[] =
	/* all of the child parts have invalid content transfer encoding */
"Content-Type: multipart/mixed; boundary=\"1\"\n"
"MIME-Version: 1.0\n\n"
"--1\n"
"Content-Transfer-Encoding: 6bit\n"
"Content-Type: text/plain; charset=UTF-8\n\n"
"Move black king to queen's bishop\n\n"
"--1\n"
"Content-Transfer-Encoding:		     7bits\n"
"Content-Type: text/plain; charset=UTF-8\n\n"
"Move \xE2\x99\x9A to \xE2\x99\x9B's \xE2\x99\x9D\n\n"
"--1\n"
"Content-Transfer-Encoding: 8 bit\n"
"Content-Type: text/plain; charset=UTF-8\n\n"
"Move \xE2\x99\x9A to \xE2\x99\x9B's \xE2\x99\x9D\n\n"
"--1\n"
"Content-Transfer-Encoding:\n"
"Content-Type: text/plain; charset=UTF-8\n\n"
"Move =E2=99=9A to =E2=99=9B's =E2=99=9D\n\n"
"--1--\n";

	const char *test_message_output = "";

	test_begin("message decoder content transfer invalid encoding");

	const struct message_parser_settings parser_set = { .flags = 0 };
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_part *parts, *part;
	struct message_block input, output;
	struct istream *istream;
	string_t *str_out = t_str_new(20);
	int ret;

	pool_t pool = pool_alloconly_create("message parser", 10240);
	istream = test_istream_create_data(test_message_input,
					   sizeof(test_message_input)-1);
	parser = message_parser_init(pool, istream, &parser_set);
	decoder = message_decoder_init(NULL, 0);

	while ((ret = message_parser_parse_next_block(parser, &input)) > 0) {
		message_part_data_parse_from_header(pool, input.part, input.hdr);
		if (input.hdr != NULL &&
		    strcasecmp(input.hdr->name, "content-transfer-encoding") == 0) {
			enum message_cte cte = message_decoder_parse_cte(input.hdr);
			test_assert(cte == MESSAGE_CTE_UNKNOWN);
		}
		if (message_decoder_decode_next_block(decoder, &input, &output) &&
		    output.hdr == NULL && output.size > 0)
			str_append_data(str_out, output.data, output.size);
	}

	test_assert_strcmp(test_message_output, str_c(str_out));
	message_decoder_deinit(&decoder);
	message_parser_deinit(&parser, &parts);
	test_assert(istream->stream_errno == 0);

	part = parts;
	test_assert(part->children_count == 4);
	part = part->children;
	test_assert_strcmp(part->data->content_type, "text");
	test_assert_strcmp(part->data->content_subtype, "plain");
	test_assert_strcmp(part->data->content_transfer_encoding, "6bit");
	test_assert_strcmp(part->data->content_type, "text");

	part = part->next;
	test_assert_strcmp(part->data->content_transfer_encoding, "7bits");
	test_assert_strcmp(part->data->content_type, "text");
	test_assert_strcmp(part->data->content_subtype, "plain");
	part = part->next;
	test_assert(part->data->content_transfer_encoding == NULL);
	part = part->next;
	test_assert(part->data->content_transfer_encoding == NULL);
	test_assert(part->next == NULL);
	i_stream_unref(&istream);
	pool_unref(&pool);
	test_end();
}


int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_decoder,
		test_message_decoder_multipart,
		test_message_decoder_current_content_type,
		test_message_decoder_content_transfer_encoding,
		test_message_decoder_invalid_content_transfer_encoding,
		NULL
	};
	return test_run(test_functions);
}
