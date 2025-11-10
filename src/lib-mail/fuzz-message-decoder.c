/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "test-common.h"
#include "fuzzer.h"
#include "message-parser.h"
#include "message-decoder.h"

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	struct istream *input = test_istream_create_data(data, size);
	const struct message_parser_settings set = {
		.hdr_flags = 0,
		.flags = MESSAGE_PARSER_FLAG_INCLUDE_MULTIPART_BLOCKS,
		.max_nested_mime_parts = 0,
		.max_total_mime_parts = 0,
	};
	struct message_parser_ctx *ctx =
		message_parser_init(pool_datastack_create(), input, &set);
	struct message_block block, block_normalized;
	struct message_decoder_context *dctx =
		message_decoder_init(uni_utf8_write_nfc, 0);

	while (message_parser_parse_next_block(ctx, &block) > -1)
		message_decoder_decode_next_block(dctx, &block, &block_normalized);

	struct message_part *part ATTR_UNUSED;
	message_decoder_deinit(&dctx);
	message_parser_deinit(&ctx, &part);
	i_stream_unref(&input);
}
FUZZ_END
