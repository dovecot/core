/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "istream-private.h"
#include "message-parser.h"
#include "istream-binary-converter.h"

#define BASE64_BLOCK_INPUT_SIZE 3
#define BASE64_BLOCK_SIZE 4
#define BASE64_BLOCKS_PER_LINE (76/BASE64_BLOCK_SIZE)
#define MAX_HDR_BUFFER_SIZE (1024*32)

struct binary_converter_istream {
	struct istream_private istream;

	pool_t pool;
	struct message_parser_ctx *parser;
	struct message_part *convert_part;
	char base64_delayed[BASE64_BLOCK_INPUT_SIZE-1];
	unsigned int base64_delayed_len;
	unsigned int base64_block_pos;

	buffer_t *hdr_buf;
	size_t cte_header_len;
	bool content_type_seen:1;
};

static void stream_add_data(struct binary_converter_istream *bstream,
			    const void *data, size_t size);

static bool part_can_convert(const struct message_part *part)
{
	/* some MUAs use "c-t-e: binary" for multiparts.
	   we don't want to convert them. */
	return (part->flags & MESSAGE_PART_FLAG_MULTIPART) == 0;
}

static void
stream_finish_convert_decision(struct binary_converter_istream *bstream)
{
	buffer_t *buf = bstream->hdr_buf;
	const unsigned char *data;

	i_assert(bstream->convert_part != NULL);

	bstream->hdr_buf = NULL;
	if (!part_can_convert(bstream->convert_part)) {
		bstream->convert_part = NULL;
		stream_add_data(bstream, buf->data, buf->used);
	} else {
		stream_add_data(bstream,
			"Content-Transfer-Encoding: base64\r\n", 35);

		data = CONST_PTR_OFFSET(buf->data, bstream->cte_header_len);
		stream_add_data(bstream, data,
				buf->used - bstream->cte_header_len);
	}
	buffer_free(&buf);
}

static void stream_add_data(struct binary_converter_istream *bstream,
			    const void *data, size_t size)
{
	if (size == 0)
		return;

	if (bstream->hdr_buf != NULL) {
		if (bstream->hdr_buf->used + size <= MAX_HDR_BUFFER_SIZE) {
			buffer_append(bstream->hdr_buf, data, size);
			return;
		}
		/* buffer is getting too large. just finish the decision. */
		stream_finish_convert_decision(bstream);
	}

	memcpy(i_stream_alloc(&bstream->istream, size), data, size);
	bstream->istream.pos += size;
}

static void stream_encode_base64(struct binary_converter_istream *bstream,
				 const void *_data, size_t size)
{
	struct istream_private *stream = &bstream->istream;
	const unsigned char *data = _data;
	buffer_t buf;
	void *dest;
	size_t encode_size, max_encoded_size;
	unsigned char base64_block[BASE64_BLOCK_INPUT_SIZE];
	unsigned int base64_block_len, missing_len, encode_blocks;

	if (bstream->base64_delayed_len > 0) {
		if (bstream->base64_delayed_len == 1 && size == 1) {
			bstream->base64_delayed[1] = data[0];
			bstream->base64_delayed_len++;
			return;
		}
		memcpy(base64_block, bstream->base64_delayed,
		       bstream->base64_delayed_len);
		base64_block_len = bstream->base64_delayed_len;
		if (size == 0) {
			/* finish base64 */
		} else {
			missing_len = BASE64_BLOCK_INPUT_SIZE - base64_block_len;
			i_assert(size >= missing_len);
			memcpy(base64_block + base64_block_len,
			       data, missing_len);
			data += missing_len;
			size -= missing_len;
			base64_block_len = BASE64_BLOCK_INPUT_SIZE;
		}

		if (bstream->base64_block_pos == BASE64_BLOCKS_PER_LINE) {
			memcpy(i_stream_alloc(stream, 2), "\r\n", 2);
			stream->pos += 2;
			bstream->base64_block_pos = 0;
		}

		dest = i_stream_alloc(stream, BASE64_BLOCK_SIZE);
		buffer_create_from_data(&buf, dest, BASE64_BLOCK_SIZE);
		base64_encode(base64_block, base64_block_len, &buf);
		stream->pos += buf.used;
		bstream->base64_block_pos++;
		bstream->base64_delayed_len = 0;
	}

	while (size >= BASE64_BLOCK_INPUT_SIZE) {
		if (bstream->base64_block_pos == BASE64_BLOCKS_PER_LINE) {
			memcpy(i_stream_alloc(stream, 2), "\r\n", 2);
			stream->pos += 2;
			bstream->base64_block_pos = 0;
		}

		/* try to encode one full line of base64 blocks */
		encode_size = I_MIN(size, BASE64_BLOCKS_PER_LINE*BASE64_BLOCK_SIZE);
		if (encode_size % BASE64_BLOCK_INPUT_SIZE != 0)
			encode_size -= encode_size % BASE64_BLOCK_INPUT_SIZE;
		encode_blocks = encode_size/BASE64_BLOCK_INPUT_SIZE;
		if (bstream->base64_block_pos + encode_blocks > BASE64_BLOCKS_PER_LINE) {
			encode_blocks = BASE64_BLOCKS_PER_LINE -
				bstream->base64_block_pos;
			encode_size = encode_blocks * BASE64_BLOCK_INPUT_SIZE;
		}

		max_encoded_size = MAX_BASE64_ENCODED_SIZE(encode_size);
		dest = i_stream_alloc(stream, max_encoded_size);
		buffer_create_from_data(&buf, dest, max_encoded_size);
		base64_encode(data, encode_size, &buf);
		stream->pos += buf.used;
		bstream->base64_block_pos += encode_blocks;

		data += encode_size;
		size -= encode_size;
	}
	if (size > 0) {
		/* encode these when more data is available */
		i_assert(size < BASE64_BLOCK_INPUT_SIZE);
		memcpy(bstream->base64_delayed, data, size);
		bstream->base64_delayed_len = size;
	}
}

static void stream_add_hdr(struct binary_converter_istream *bstream,
			   const struct message_header_line *hdr)
{
	if (!hdr->continued) {
		stream_add_data(bstream, hdr->name, hdr->name_len);
		stream_add_data(bstream, hdr->middle, hdr->middle_len);
	}

	stream_add_data(bstream, hdr->value, hdr->value_len);
	if (!hdr->no_newline)
		stream_add_data(bstream, "\r\n", 2);
}

static ssize_t i_stream_binary_converter_read(struct istream_private *stream)
{
	/* @UNSAFE */
	struct binary_converter_istream *bstream =
		(struct binary_converter_istream *)stream;
	struct message_block block;
	size_t old_size, new_size;

	if (stream->pos - stream->skip >= i_stream_get_max_buffer_size(&stream->istream))
		return -2;
	old_size = stream->pos - stream->skip;

	switch (message_parser_parse_next_block(bstream->parser, &block)) {
	case -1:
		/* done / error */
		if (bstream->convert_part != NULL &&
		    bstream->base64_delayed_len > 0) {
			/* flush any pending base64 output */
			stream_encode_base64(bstream, "", 0);
			new_size = stream->pos - stream->skip;
			i_assert(old_size != new_size);
			return new_size - old_size;
		}
		stream->istream.eof = TRUE;
		stream->istream.stream_errno = stream->parent->stream_errno;
		return -1;
	case 0:
		/* need more data */
		return 0;
	default:
		break;
	}

	if (block.part != bstream->convert_part &&
	    bstream->convert_part != NULL) {
		/* end of base64 encoded part */
		stream_encode_base64(bstream, "", 0);
	}

	if (block.hdr != NULL) {
		/* parsing a header */
		if (strcasecmp(block.hdr->name, "Content-Type") == 0)
			bstream->content_type_seen = TRUE;

		if (strcasecmp(block.hdr->name, "Content-Transfer-Encoding") == 0 &&
			 !block.hdr->continued && !block.hdr->continues &&
			 block.hdr->value_len == 6 &&
			 i_memcasecmp(block.hdr->value, "binary", 6) == 0 &&
			 part_can_convert(block.part) &&
			 bstream->convert_part != block.part) {
			/* looks like we want to convert this body part to
			   base64, but if we haven't seen Content-Type yet
			   delay the decision until we've read the rest of
			   the header */
			i_assert(block.part != NULL);
			bstream->convert_part = block.part;
			bstream->base64_block_pos = 0;
			if (!bstream->content_type_seen) {
				i_assert(bstream->hdr_buf == NULL);
				bstream->hdr_buf = buffer_create_dynamic(default_pool, 512);
				stream_add_hdr(bstream, block.hdr);
				bstream->cte_header_len = bstream->hdr_buf->used;
			} else {
				stream_add_data(bstream,
					"Content-Transfer-Encoding: base64\r\n", 35);
			}
		} else if (block.hdr->eoh && bstream->hdr_buf != NULL) {
			/* finish the decision about decoding */
			stream_finish_convert_decision(bstream);
			stream_add_data(bstream, "\r\n", 2);
		} else {
			stream_add_hdr(bstream, block.hdr);
		}
	} else if (block.size == 0) {
		/* end of header */
		if (bstream->hdr_buf != NULL) {
			/* message has no body */
			bstream->convert_part = NULL;
			stream_add_data(bstream, bstream->hdr_buf->data,
					bstream->hdr_buf->used);
			buffer_free(&bstream->hdr_buf);
		}
		bstream->content_type_seen = FALSE;
	} else if (block.part == bstream->convert_part) {
		/* convert body part to base64 */
		stream_encode_base64(bstream, block.data, block.size);
	} else {
		stream_add_data(bstream, block.data, block.size);
	}
	new_size = stream->pos - stream->skip;
	if (new_size == old_size)
		return i_stream_binary_converter_read(stream);
	return new_size - old_size;
}

static void i_stream_binary_converter_close(struct iostream_private *stream,
					    bool close_parent)
{
	struct binary_converter_istream *bstream =
		(struct binary_converter_istream *)stream;
	struct message_part *parts;

	if (bstream->parser != NULL) {
		message_parser_deinit(&bstream->parser, &parts);
	}
	pool_unref(&bstream->pool);
	if (close_parent)
		i_stream_close(bstream->istream.parent);
}

struct istream *i_stream_create_binary_converter(struct istream *input)
{
	const struct message_parser_settings parser_set = {
		.flags = MESSAGE_PARSER_FLAG_INCLUDE_MULTIPART_BLOCKS |
			MESSAGE_PARSER_FLAG_INCLUDE_BOUNDARIES,
	};
	struct binary_converter_istream *bstream;

	bstream = i_new(struct binary_converter_istream, 1);
	bstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	bstream->istream.read = i_stream_binary_converter_read;
	bstream->istream.iostream.close = i_stream_binary_converter_close;

	bstream->istream.istream.readable_fd = FALSE;
	bstream->istream.istream.blocking = input->blocking;
	bstream->istream.istream.seekable = FALSE;

	bstream->pool = pool_alloconly_create("istream binary converter", 128);
	bstream->parser = message_parser_init(bstream->pool, input, &parser_set);
	return i_stream_create(&bstream->istream, input,
			       i_stream_get_fd(input), 0);
}
