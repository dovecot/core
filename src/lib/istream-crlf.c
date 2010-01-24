/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"
#include "istream-crlf.h"

struct crlf_istream {
	struct istream_private istream;

	unsigned int pending_cr:1;
	unsigned int last_cr:1;
};

static int i_stream_crlf_read_common(struct crlf_istream *cstream)
{
	struct istream_private *stream = &cstream->istream;
	size_t size;
	ssize_t ret;

	(void)i_stream_get_data(stream->parent, &size);
	if (size == 0) {
		ret = i_stream_read(stream->parent);
		if (ret <= 0 && (ret != -2 || stream->skip == 0)) {
			stream->istream.stream_errno =
				stream->parent->stream_errno;
			stream->istream.eof = stream->parent->eof;
			return ret;
		}
		(void)i_stream_get_data(stream->parent, &size);
		i_assert(size != 0);
	}

	if (!i_stream_get_buffer_space(stream, size, NULL))
		return -2;
	return 1;
}

static ssize_t i_stream_crlf_read_crlf(struct istream_private *stream)
{
	struct crlf_istream *cstream = (struct crlf_istream *)stream;
	const unsigned char *data;
	size_t i, dest, size;
	ssize_t ret;

	ret = i_stream_crlf_read_common(cstream);
	if (ret <= 0)
		return ret;

	data = i_stream_get_data(stream->parent, &size);

	/* @UNSAFE: add missing CRs */
	dest = stream->pos;
	for (i = 0; i < size && dest < stream->buffer_size; i++) {
		if (data[i] == '\n') {
			if (i == 0) {
				if (!cstream->last_cr)
					stream->w_buffer[dest++] = '\r';
			} else {
				if (data[i-1] != '\r')
					stream->w_buffer[dest++] = '\r';
			}
			if (dest == stream->buffer_size)
				break;
		}
		stream->w_buffer[dest++] = data[i];
	}
	cstream->last_cr = stream->w_buffer[dest-1] == '\r';
	i_stream_skip(stream->parent, i);

	ret = dest - stream->pos;
	i_assert(ret > 0);
	stream->pos = dest;
	return ret;
}

static ssize_t i_stream_crlf_read_lf(struct istream_private *stream)
{
	struct crlf_istream *cstream = (struct crlf_istream *)stream;
	const unsigned char *data;
	size_t i, dest, size;
	ssize_t ret;
	int diff;

	ret = i_stream_crlf_read_common(cstream);
	if (ret <= 0)
		return ret;

	data = i_stream_get_data(stream->parent, &size);

	/* @UNSAFE */
	dest = stream->pos;
	if (data[0] == '\n') {
		stream->w_buffer[dest++] = '\n';
		cstream->pending_cr = FALSE;
	} else {
		if (cstream->pending_cr) {
			/* CR without LF */
			stream->w_buffer[dest++] = '\r';
			if (dest == stream->buffer_size) {
				stream->pos++;
				cstream->pending_cr = FALSE;
				return 1;
			}
		}
		if (data[0] != '\r')
			stream->w_buffer[dest++] = data[0];
	}

	diff = -1;
	for (i = 1; i < size && dest < stream->buffer_size; i++) {
		if (data[i] == '\r') {
			if (data[i-1] != '\r')
				continue;
		} else if (data[i-1] == '\r' && data[i] != '\n') {
			stream->w_buffer[dest++] = '\r';
			if (dest == stream->buffer_size) {
				diff = 0;
				break;
			}
		}

		stream->w_buffer[dest++] = data[i];
	}
	cstream->pending_cr = data[i+diff] == '\r';
	i_stream_skip(stream->parent, i);

	ret = dest - stream->pos;
	if (ret == 0) {
		i_assert(cstream->pending_cr && size == 1);
		return i_stream_crlf_read_lf(stream);
	}
	i_assert(ret > 0);
	stream->pos = dest;
	return ret;
}

static const struct stat *
i_stream_crlf_stat(struct istream_private *stream, bool exact)
{
	return i_stream_stat(stream->parent, exact);
}

static struct istream *
i_stream_create_crlf_full(struct istream *input, bool crlf)
{
	struct crlf_istream *cstream;

	cstream = i_new(struct crlf_istream, 1);
	cstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	cstream->istream.read = crlf ? i_stream_crlf_read_crlf :
		i_stream_crlf_read_lf;
	cstream->istream.stat = i_stream_crlf_stat;

	cstream->istream.istream.readable_fd = FALSE;
	cstream->istream.istream.blocking = input->blocking;
	cstream->istream.istream.seekable = FALSE;
	return i_stream_create(&cstream->istream, input,
			       i_stream_get_fd(input));
}

struct istream *i_stream_create_crlf(struct istream *input)
{
	return i_stream_create_crlf_full(input, TRUE);
}

struct istream *i_stream_create_lf(struct istream *input)
{
	return i_stream_create_crlf_full(input, FALSE);
}
