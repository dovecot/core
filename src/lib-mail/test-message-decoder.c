/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "charset-utf8.h"
#include "quoted-printable.h"
#include "message-parser.h"
#include "message-header-decode.h"
#include "message-decoder.h"
#include "test-common.h"

bool message_header_decode_utf8(const unsigned char *data, size_t size,
				buffer_t *dest, bool dtcase ATTR_UNUSED)
{
	buffer_append(dest, data, size);
	return FALSE;
}

void quoted_printable_decode(const unsigned char *src, size_t src_size,
			     size_t *src_pos_r, buffer_t *dest)
{
	while (src_size > 0 && src[src_size-1] == ' ')
		src_size--;
	buffer_append(dest, src, src_size);
	*src_pos_r = src_size;
}

int charset_to_utf8_begin(const char *charset ATTR_UNUSED,
			  enum charset_flags flags ATTR_UNUSED,
			  struct charset_translation **t_r)
{
	*t_r = NULL;
	return 0;
}
void charset_to_utf8_end(struct charset_translation **t ATTR_UNUSED) { }
bool charset_is_utf8(const char *charset ATTR_UNUSED) { return TRUE; }

enum charset_result
charset_to_utf8(struct charset_translation *t ATTR_UNUSED,
		const unsigned char *src, size_t *src_size, buffer_t *dest)
{
	buffer_append(dest, src, *src_size);
	return CHARSET_RET_OK;
}

static void test_message_decoder(void)
{
	struct message_decoder_context *ctx;
	struct message_part part;
	struct message_header_line hdr;
	struct message_block input, output;

	test_begin("message decoder");

	memset(&part, 0, sizeof(part));
	memset(&input, 0, sizeof(input));
	memset(&output, 0, sizeof(output));
	input.part = &part;

	ctx = message_decoder_init(0);

	memset(&hdr, 0, sizeof(hdr));
	hdr.name = "Content-Transfer-Encoding";
	hdr.name_len = strlen(hdr.name);
	hdr.full_value = (const void *)"quoted-printable";
	hdr.full_value_len = strlen((const char *)hdr.full_value);
	input.hdr = &hdr;
	test_assert(message_decoder_decode_next_block(ctx, &input, &output));

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

	message_decoder_deinit(&ctx);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_decoder,
		NULL
	};
	return test_run(test_functions);
}
