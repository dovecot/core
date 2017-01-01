/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "charset-utf8.h"
#include "message-parser.h"
#include "message-header-decode.h"
#include "message-decoder.h"
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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_decoder,
		test_message_decoder_current_content_type,
		NULL
	};
	return test_run(test_functions);
}
