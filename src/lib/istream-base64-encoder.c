/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "istream-private.h"
#include "istream-base64.h"

struct base64_encoder_istream {
	struct istream_private istream;

	struct base64_encoder encoder;
};

static int i_stream_read_parent(struct istream_private *stream)
{
	size_t size;
	ssize_t ret;

	size = i_stream_get_data_size(stream->parent);
	if (size > 0)
		return 1;

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
i_stream_base64_try_encode(struct base64_encoder_istream *bstream)
{
	struct istream_private *stream = &bstream->istream;
	struct base64_encoder *b64enc = &bstream->encoder;
	const unsigned char *data;
	size_t size, pos, out_size, avail;
	buffer_t buf;

	data = i_stream_get_data(stream->parent, &size);
	if (size == 0)
		return 0;

	out_size = base64_encode_get_size(b64enc, size);
	if (!i_stream_try_alloc(stream, out_size, &avail))
		return -2;

	buffer_create_from_data(&buf, stream->w_buffer + stream->pos, avail);
	base64_encode_more(b64enc, data, size, &pos, &buf);
	i_assert(buf.used > 0);

	stream->pos += buf.used;
	i_stream_skip(stream->parent, pos);
	return 1;
}

static int
i_stream_base64_finish_encode(struct base64_encoder_istream *bstream)
{
	struct istream_private *stream = &bstream->istream;
	struct base64_encoder *b64enc = &bstream->encoder;
	size_t out_size, buffer_avail;
	buffer_t buf;

	out_size = base64_encode_get_size(b64enc, 0);
	if (out_size == 0) {
		if (base64_encode_finish(b64enc, NULL))
			stream->istream.eof = TRUE;
		return 1;
	}

	if (!i_stream_try_alloc(stream, out_size, &buffer_avail))
		return -2;

	buffer_create_from_data(&buf, stream->w_buffer + stream->pos,
				buffer_avail);
	if (base64_encode_finish(b64enc, &buf))
		stream->istream.eof = TRUE;
	i_assert(buf.used > 0);

	stream->pos += buf.used;
	return 1;
}

static ssize_t i_stream_base64_encoder_read(struct istream_private *stream)
{
	struct base64_encoder_istream *bstream =
		(struct base64_encoder_istream *)stream;
	size_t pre_count, post_count;
	int ret;

	if (base64_encode_is_finished(&bstream->encoder)) {
		stream->istream.eof = TRUE;
		return -1;
	}

	pre_count = post_count = 0;
	do {
		ret = i_stream_read_parent(stream);
		if (ret == 0)
			return 0;
		if (ret < 0) {
			if (stream->istream.stream_errno != 0)
				return -1;
			if (i_stream_get_data_size(stream->parent) == 0)
				break;
			/* add the final partial block */
		}

		/* encode as many lines as fits into destination buffer */
		pre_count = stream->pos - stream->skip;
		while ((ret = i_stream_base64_try_encode(bstream)) > 0) ;
		post_count = stream->pos - stream->skip;
	} while (ret == 0 && pre_count == post_count);

	if (ret == -2) {
		if (pre_count == post_count)
			return -2;
	} else if (ret < 0) {
		if (i_stream_get_data_size(stream->parent) == 0) {
			i_assert(post_count == pre_count);
			pre_count = stream->pos - stream->skip;
			ret = i_stream_base64_finish_encode(bstream);
			post_count = stream->pos - stream->skip;
			if (ret <= 0)
				return ret;
		}
		if (pre_count == post_count) {
			stream->istream.eof = TRUE;
			return -1;
		}
	}

	i_assert(post_count > pre_count);
	return post_count - pre_count;
}

static void
i_stream_base64_encoder_seek(struct istream_private *stream,
			     uoff_t v_offset, bool mark)
{
	struct base64_encoder_istream *bstream =
		(struct base64_encoder_istream *)stream;

	if (v_offset < stream->istream.v_offset) {
		/* seeking backwards - go back to beginning and seek
		   forward from there. */
		stream->parent_expected_offset = stream->parent_start_offset;
		stream->skip = stream->pos = 0;
		stream->istream.v_offset = 0;
		i_stream_seek(stream->parent, 0);

		base64_encode_reset(&bstream->encoder);
	}
	i_stream_default_seek_nonseekable(stream, v_offset, mark);
}

static int
i_stream_base64_encoder_stat(struct istream_private *stream,
	bool exact ATTR_UNUSED)
{
	struct base64_encoder_istream *bstream =
		(struct base64_encoder_istream *)stream;
	const struct stat *st;

	if (i_stream_stat(stream->parent, exact, &st) < 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		return -1;
	}

	stream->statbuf = *st;
	if (st->st_size == 0)
		return 0;

	stream->statbuf.st_size =
		base64_get_full_encoded_size(&bstream->encoder, st->st_size);
	return 0;
}

static struct istream *
i_stream_create_base64_encoder_common(const struct base64_scheme *b64,
				      struct istream *input,
				      unsigned int chars_per_line, bool crlf)
{
	struct base64_encoder_istream *bstream;
	enum base64_encode_flags b64_flags = 0;

	i_assert(chars_per_line % 4 == 0);

	bstream = i_new(struct base64_encoder_istream, 1);
	bstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	bstream->istream.read = i_stream_base64_encoder_read;
	bstream->istream.seek = i_stream_base64_encoder_seek;
	bstream->istream.stat = i_stream_base64_encoder_stat;

	bstream->istream.istream.readable_fd = FALSE;
	bstream->istream.istream.blocking = input->blocking;
	bstream->istream.istream.seekable = input->seekable;

	if (crlf)
		b64_flags |= BASE64_ENCODE_FLAG_CRLF;
	base64_encode_init(&bstream->encoder, b64, b64_flags, chars_per_line);

	return i_stream_create(&bstream->istream, input,
			       i_stream_get_fd(input), 0);
}

struct istream *
i_stream_create_base64_encoder(struct istream *input,
			       unsigned int chars_per_line, bool crlf)
{
	return i_stream_create_base64_encoder_common(&base64_scheme, input,
						     chars_per_line, crlf);
}

struct istream *
i_stream_create_base64url_encoder(struct istream *input,
				  unsigned int chars_per_line, bool crlf)
{
	return i_stream_create_base64_encoder_common(&base64url_scheme, input,
						     chars_per_line, crlf);
}
