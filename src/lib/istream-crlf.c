/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"
#include "istream-crlf.h"

struct crlf_istream {
	struct istream_private istream;

	struct istream *input;
	char last_char;
	unsigned int crlf:1;
};

static void i_stream_crlf_destroy(struct iostream_private *stream)
{
	struct crlf_istream *cstream = (struct crlf_istream *)stream;

	i_stream_unref(&cstream->input);
}

static void
i_stream_crlf_set_max_buffer_size(struct iostream_private *stream,
				   size_t max_size)
{
	struct crlf_istream *cstream = (struct crlf_istream *)stream;

	cstream->istream.max_buffer_size = max_size;
	i_stream_set_max_buffer_size(cstream->input, max_size);
}

static ssize_t i_stream_crlf_read(struct istream_private *stream)
{
	struct crlf_istream *cstream = (struct crlf_istream *)stream;
	const unsigned char *data;
	size_t i, dest, size;
	ssize_t ret;

	data = i_stream_get_data(cstream->input, &size);
	if (size <= stream->pos) {
		ret = i_stream_read(cstream->input);
		if (ret <= 0 && (ret != -2 || stream->skip == 0)) {
			stream->istream.stream_errno =
				cstream->input->stream_errno;
			stream->istream.eof = cstream->input->eof;
			return ret;
		}
	}

	data = i_stream_get_data(cstream->input, &size);
	i_assert(size != 0);

	if (!i_stream_get_buffer_space(stream, size, NULL))
		return -2;

	/* @UNSAFE */
	dest = stream->pos;
	if (data[0] == '\n')
		i = 0;
	else {
		if (cstream->last_char == '\r') {
			/* CR without LF */
			stream->w_buffer[dest++] = '\r';
			if (dest == stream->buffer_size) {
				cstream->last_char = 0;
				return 1;
			}
		}
		if (data[0] != '\r')
			stream->w_buffer[dest++] = data[0];
		i = 1;
	}
	cstream->last_char = data[size-1];
	for (; i < size && dest < stream->buffer_size; i++) {
		if (data[i] <= '\r') {
			if (data[i] == '\n') {
				if (cstream->crlf) {
					if (dest + 1 == stream->buffer_size)
						break;
					stream->w_buffer[dest++] = '\r';
				}
				stream->w_buffer[dest++] = '\n';
				continue;
			}
			if (data[i] == '\r' && data[i-1] != '\r')
				continue;
		}
		if (data[i-1] == '\r') {
			/* CR without LF */
			stream->w_buffer[dest++] = '\r';
			if (dest == stream->buffer_size) {
				cstream->last_char = 0;
				break;
			}
			if (data[i] == '\r')
				continue;
		}
		stream->w_buffer[dest++] = data[i];
	}
	i_stream_skip(cstream->input, i);

	ret = dest - stream->pos;
	i_assert(ret > 0);
	stream->pos = dest;
	return ret;
}

static void ATTR_NORETURN
i_stream_crlf_seek(struct istream_private *stream ATTR_UNUSED,
		   uoff_t v_offset ATTR_UNUSED, bool mark ATTR_UNUSED)
{
	i_panic("crlf-istream: seeking unsupported currently");
}

static const struct stat *
i_stream_crlf_stat(struct istream_private *stream, bool exact)
{
	struct crlf_istream *cstream = (struct crlf_istream *)stream;

	return i_stream_stat(cstream->input, exact);
}

static struct istream *
i_stream_create_crlf_full(struct istream *input, bool crlf)
{
	struct crlf_istream *cstream;

	i_stream_ref(input);

	cstream = i_new(struct crlf_istream, 1);
	cstream->input = input;
	cstream->crlf = crlf;
	cstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	cstream->istream.iostream.destroy = i_stream_crlf_destroy;
	cstream->istream.iostream.set_max_buffer_size =
		i_stream_crlf_set_max_buffer_size;

	cstream->istream.read = i_stream_crlf_read;
	cstream->istream.seek = i_stream_crlf_seek;
	cstream->istream.stat = i_stream_crlf_stat;

	cstream->istream.istream.blocking = input->blocking;
	cstream->istream.istream.seekable = input->seekable;
	return i_stream_create(&cstream->istream, i_stream_get_fd(input), 0);
}

struct istream *i_stream_create_crlf(struct istream *input)
{
	return i_stream_create_crlf_full(input, TRUE);
}

struct istream *i_stream_create_lf(struct istream *input)
{
	return i_stream_create_crlf_full(input, FALSE);
}
