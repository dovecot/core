/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "test-common.h"
#include "test-common.h"
#include "fuzzer.h"
#include "message-parser.h"

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
	struct message_block block ATTR_UNUSED;
	i_zero(&block);
	while(message_parser_parse_next_block(ctx, &block) > -1);
	struct message_part *part ATTR_UNUSED;
	message_parser_deinit(&ctx, &part);
	i_stream_unref(&input);
}
FUZZ_END
