/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "istream-private.h"
#include "istream-base64.h"

struct base64_encoder_istream {
	struct istream_private istream;

	const struct base64_scheme *b64;

	/* current encoded line length. */
	size_t cur_line_len;

	unsigned int chars_per_line;
	bool crlf;
};

static int i_stream_read_parent(struct istream_private *stream)
{
	size_t size;
	ssize_t ret;

	size = i_stream_get_data_size(stream->parent);
	if (size >= 3)
		return 1;

	/* we have less than one base64 block.
	   see if there is more data available. */
	ret = i_stream_read_memarea(stream->parent);
	if (ret <= 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		stream->istream.eof = stream->parent->eof;
		return ret;
	}
	size = i_stream_get_data_size(stream->parent);
	i_assert(size != 0);
	return 1;
}

static int
i_stream_base64_try_encode_line(struct base64_encoder_istream *bstream)
{
	struct istream_private *stream = &bstream->istream;
	const unsigned char *data;
	size_t size, avail, buffer_avail;
	buffer_t buf;

	data = i_stream_get_data(stream->parent, &size);
	if (size == 0 || (size < 3 && !stream->parent->eof))
		return 0;

	if (bstream->cur_line_len == bstream->chars_per_line) {
		/* @UNSAFE: end of line, add newline */
		if (!i_stream_try_alloc(stream, bstream->crlf ? 2 : 1, &avail))
			return -2;

		if (bstream->crlf)
			stream->w_buffer[stream->pos++] = '\r';
		stream->w_buffer[stream->pos++] = '\n';
		bstream->cur_line_len = 0;
	}

	i_stream_try_alloc(stream, (size+2)/3*4, &avail);
	buffer_avail = stream->buffer_size - stream->pos;

	if ((size + 2) / 3 * 4 > buffer_avail) {
		/* can't fit everything to destination buffer.
		   write as much as we can. */
		size = (buffer_avail / 4) * 3;
		if (size == 0)
			return -2;
	} else if (!stream->parent->eof && size % 3 != 0) {
		/* encode 3 chars at a time, so base64_encode() doesn't
		   add '=' characters in the middle of the stream */
		size -= (size % 3);
	}
	i_assert(size != 0);

	if (bstream->cur_line_len + (size+2)/3*4 > bstream->chars_per_line) {
		size = (bstream->chars_per_line - bstream->cur_line_len)/4 * 3;
		i_assert(size != 0);
	}

	buffer_create_from_data(&buf, stream->w_buffer + stream->pos,
				buffer_avail);
	base64_scheme_encode(bstream->b64, data, size, &buf);
	i_assert(buf.used > 0);

	bstream->cur_line_len += buf.used;
	i_assert(bstream->cur_line_len <= bstream->chars_per_line);
	stream->pos += buf.used;
	i_stream_skip(stream->parent, size);
	return 1;
}

static ssize_t i_stream_base64_encoder_read(struct istream_private *stream)
{
	struct base64_encoder_istream *bstream =
		(struct base64_encoder_istream *)stream;
	size_t pre_count, post_count;
	int ret;

	do {
		ret = i_stream_read_parent(stream);
		if (ret == 0)
			return 0;
		if (ret < 0) {
			if (i_stream_get_data_size(stream->parent) == 0)
				return -1;
			/* add the final partial block */
		}

		/* encode as many lines as fits into destination buffer */
		pre_count = stream->pos - stream->skip;
		while ((ret = i_stream_base64_try_encode_line(bstream)) > 0) ;
		post_count = stream->pos - stream->skip;
	} while (ret == 0 && pre_count == post_count);

	if (ret < 0 && pre_count == post_count)
		return ret;

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
		bstream->cur_line_len = 0;
		i_stream_seek(stream->parent, 0);
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
	off_t newlines, size;

	if (i_stream_stat(stream->parent, exact, &st) < 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		return -1;
	}

	stream->statbuf = *st;
	if (st->st_size == 0)
		return 0;
	
	/* calculate size of encoded data */
	size = (st->st_size / 3) * 4 +
		((st->st_size % 3) == 0 ? 0 : 4);

	/* update size with added newlines */
	newlines = (size / bstream->chars_per_line - 1) +
		((size % bstream->chars_per_line) == 0 ? 0 : 1);
	size += newlines * (bstream->crlf ? 2 : 1);

	stream->statbuf.st_size = size;
	return 0;
}

static struct istream *
i_stream_create_base64_encoder_common(const struct base64_scheme *b64,
				      struct istream *input,
				      unsigned int chars_per_line, bool crlf)
{
	struct base64_encoder_istream *bstream;

	i_assert(chars_per_line % 4 == 0);

	bstream = i_new(struct base64_encoder_istream, 1);
	bstream->b64 = b64;
	bstream->chars_per_line = chars_per_line;
	bstream->crlf = crlf;
	bstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	bstream->istream.read = i_stream_base64_encoder_read;
	bstream->istream.seek = i_stream_base64_encoder_seek;
	bstream->istream.stat = i_stream_base64_encoder_stat;

	bstream->istream.istream.readable_fd = FALSE;
	bstream->istream.istream.blocking = input->blocking;
	bstream->istream.istream.seekable = input->seekable;
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
