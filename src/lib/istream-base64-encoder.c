/* Copyright (c) 2003-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "istream-internal.h"
#include "istream-base64-encoder.h"

struct base64_encoder_istream {
	struct istream_private istream;

	/* current encoded line length. */
	unsigned int cur_line_len;

	unsigned int chars_per_line;
	bool crlf;
};

static int i_stream_read_parent(struct istream_private *stream)
{
	size_t size;
	ssize_t ret;

	(void)i_stream_get_data(stream->parent, &size);
	if (size >= 4)
		return 1;

	/* we have less than one base64 block.
	   see if there is more data available. */
	ret = i_stream_read(stream->parent);
	if (ret <= 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		stream->istream.eof = stream->parent->eof;
		return size > 0 ? 1 : ret;
	}
	(void)i_stream_get_data(stream->parent, &size);
	i_assert(size != 0);
	return 1;
}

static bool
i_stream_base64_try_encode_line(struct base64_encoder_istream *bstream)
{
	struct istream_private *stream = &bstream->istream;
	const unsigned char *data;
	size_t size, buffer_avail;
	buffer_t buf;

	if (bstream->cur_line_len == bstream->chars_per_line) {
		/* @UNSAFE: end of line, add newline */
		if (!i_stream_get_buffer_space(stream,
					       bstream->crlf ? 2 : 1, NULL))
			return FALSE;

		if (bstream->crlf)
			stream->w_buffer[stream->pos++] = '\r';
		stream->w_buffer[stream->pos++] = '\n';
		bstream->cur_line_len = 0;
	}
	data = i_stream_get_data(stream->parent, &size);
	if (size == 0)
		return FALSE;

	i_stream_get_buffer_space(stream, (size+2)/3*4, NULL);
	buffer_avail = stream->buffer_size - stream->pos;

	if ((size + 2) / 3 * 4 > buffer_avail) {
		/* can't fit everything to destination buffer.
		   write as much as we can. */
		size = (buffer_avail / 4) * 3;
	} else if (!stream->parent->eof && size % 3 != 0) {
		/* encode 3 chars at a time, so base64_encode() doesn't
		   add '=' characters in the middle of the stream */
		size -= (size % 3);
	}
	if (size == 0)
		return FALSE;

	if (bstream->cur_line_len + (size+2)/3*4 > bstream->chars_per_line) {
		size = (bstream->chars_per_line - bstream->cur_line_len)/4 * 3;
		i_assert(size != 0);
	}

	buffer_create_data(&buf, stream->w_buffer + stream->pos, buffer_avail);
	base64_encode(data, size, &buf);
	i_assert(buf.used > 0);

	bstream->cur_line_len += buf.used;
	i_assert(bstream->cur_line_len <= bstream->chars_per_line);
	stream->pos += buf.used;
	i_stream_skip(stream->parent, size);
	return TRUE;
}

static ssize_t i_stream_base64_encoder_read(struct istream_private *stream)
{
	struct base64_encoder_istream *bstream =
		(struct base64_encoder_istream *)stream;
	size_t pre_count, post_count;
	int ret;

	ret = i_stream_read_parent(stream);
	if (ret <= 0)
		return ret;

	/* encode as many lines as fits into destination buffer */
	pre_count = stream->pos - stream->skip;
	while (i_stream_base64_try_encode_line(bstream)) ;
	post_count = stream->pos - stream->skip;

	if (pre_count == post_count) {
		i_assert(stream->buffer_size - stream->pos < 4);
		return -2;
	}

	i_assert(post_count > pre_count);
	return post_count - pre_count;
}

static const struct stat *
i_stream_base64_encoder_stat(struct istream_private *stream, bool exact)
{
	if (exact) {
		/* too much trouble to implement until it's actually needed */
		i_panic("istream-base64-encoder: "
			"stat() doesn't support getting exact size");
	}
	return i_stream_stat(stream->parent, exact);
}

struct istream *
i_stream_create_base64_encoder(struct istream *input,
			       unsigned int chars_per_line, bool crlf)
{
	struct base64_encoder_istream *bstream;

	i_assert(chars_per_line % 4 == 0);

	bstream = i_new(struct base64_encoder_istream, 1);
	bstream->chars_per_line = chars_per_line;
	bstream->crlf = crlf;
	bstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	bstream->istream.parent = input;
	bstream->istream.read = i_stream_base64_encoder_read;
	bstream->istream.stat = i_stream_base64_encoder_stat;

	bstream->istream.istream.readable_fd = FALSE;
	bstream->istream.istream.blocking = input->blocking;
	bstream->istream.istream.seekable = FALSE;
	return i_stream_create(&bstream->istream, input,
			       i_stream_get_fd(input));
}
