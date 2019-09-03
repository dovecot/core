/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "hex-binary.h"
#include "istream-private.h"
#include "istream-base64.h"

struct base64_decoder_istream {
	struct istream_private istream;

	struct base64_decoder decoder;
};

static int i_stream_read_parent(struct istream_private *stream)
{
	size_t size;
	ssize_t ret;

	size = i_stream_get_data_size(stream->parent);
	if (size >= 4)
		return 1;

	/* we have less than one base64 block.
	   see if there is more data available. */
	ret = i_stream_read_memarea(stream->parent);
	if (ret <= 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		return ret;
	}
	size = i_stream_get_data_size(stream->parent);
	i_assert(size != 0);
	return 1;
}

static int
i_stream_base64_try_decode_block(struct base64_decoder_istream *bstream)
{
	struct istream_private *stream = &bstream->istream;
	const unsigned char *data;
	size_t size, avail, pos;
	buffer_t buf;

	data = i_stream_get_data(stream->parent, &size);
	if (size == 0)
		return 0;

	if (!i_stream_try_alloc(stream, (size+3)/4*3, &avail))
		return -2;

	buffer_create_from_data(&buf, stream->w_buffer + stream->pos, avail);
	if (base64_decode_more(&bstream->decoder, data, size, &pos, &buf) < 0) {
		io_stream_set_error(&stream->iostream,
			"Invalid base64 data: 0x%s",
			binary_to_hex(data+pos, I_MIN(size-pos, 8)));
		stream->istream.stream_errno = EINVAL;
		return -1;
	}

	stream->pos += buf.used;
	i_stream_skip(stream->parent, pos);
	return pos > 0 ? 1 : 0;
}

static void
i_stream_base64_finish_decode(struct base64_decoder_istream *bstream)
{
	struct istream_private *stream = &bstream->istream;

	i_assert(i_stream_get_data_size(stream->parent) ==  0);

	if (base64_decode_finish(&bstream->decoder) < 0) {
		io_stream_set_error(&stream->iostream,
			"Base64 data ends prematurely");
		stream->istream.stream_errno = EPIPE;
	}
}

static ssize_t i_stream_base64_decoder_read(struct istream_private *stream)
{
	struct base64_decoder_istream *bstream =
		(struct base64_decoder_istream *)stream;
	size_t pre_count, post_count;
	int ret;

	if (base64_decode_is_finished(&bstream->decoder)) {
		stream->istream.eof = TRUE;
		return -1;
	}

	do {
		ret = i_stream_read_parent(stream);
		if (ret == 0)
			return 0;
		if (ret < 0 && ret != -2) {
			if (stream->istream.stream_errno != 0)
				return -1;
			if (i_stream_get_data_size(stream->parent) == 0) {
				i_stream_base64_finish_decode(bstream);
				stream->istream.eof = TRUE;
				return -1;
			}
		}

		/* encode as many blocks as fits into destination buffer */
		pre_count = stream->pos - stream->skip;
		while ((ret = i_stream_base64_try_decode_block(bstream)) > 0) ;
		post_count = stream->pos - stream->skip;
	} while (ret == 0 && pre_count == post_count);

	if (ret < 0 && pre_count == post_count)
		return ret;

	i_assert(post_count > pre_count);
	return post_count - pre_count;
}

static void
i_stream_base64_decoder_seek(struct istream_private *stream,
			     uoff_t v_offset, bool mark)
{
	struct base64_decoder_istream *bstream =
		(struct base64_decoder_istream *)stream;

	if (v_offset < stream->istream.v_offset) {
		/* seeking backwards - go back to beginning and seek
		   forward from there. */
		stream->parent_expected_offset = stream->parent_start_offset;
		stream->skip = stream->pos = 0;
		stream->istream.v_offset = 0;
		i_stream_seek(stream->parent, 0);

		base64_decode_reset(&bstream->decoder);
	}
	i_stream_default_seek_nonseekable(stream, v_offset, mark);
}

static struct istream *
i_stream_create_base64_decoder_common(const struct base64_scheme *b64,
				      struct istream *input)
{
	struct base64_decoder_istream *bstream;

	bstream = i_new(struct base64_decoder_istream, 1);
	bstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	bstream->istream.read = i_stream_base64_decoder_read;
	bstream->istream.seek = i_stream_base64_decoder_seek;

	bstream->istream.istream.readable_fd = FALSE;
	bstream->istream.istream.blocking = input->blocking;
	bstream->istream.istream.seekable = input->seekable;

	base64_decode_init(&bstream->decoder, b64, 0);

	return i_stream_create(&bstream->istream, input,
			       i_stream_get_fd(input), 0);
}

struct istream *
i_stream_create_base64_decoder(struct istream *input)
{
	return i_stream_create_base64_decoder_common(&base64_scheme, input);
}

struct istream *
i_stream_create_base64url_decoder(struct istream *input)
{
	return i_stream_create_base64_decoder_common(&base64url_scheme, input);
}
