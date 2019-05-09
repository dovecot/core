/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "istream-crlf.h"

struct crlf_istream {
	struct istream_private istream;

	bool pending_cr:1;
	bool last_cr:1;
};

static int i_stream_crlf_read_common(struct crlf_istream *cstream)
{
	struct istream_private *stream = &cstream->istream;
	size_t size, avail;
	ssize_t ret;

	size = i_stream_get_data_size(stream->parent);
	if (size == 0) {
		ret = i_stream_read_memarea(stream->parent);
		if (ret <= 0) {
			i_assert(ret != -2); /* 0 sized buffer can't be full */
			stream->istream.stream_errno =
				stream->parent->stream_errno;
			stream->istream.eof = stream->parent->eof;
			return ret;
		}
		size = i_stream_get_data_size(stream->parent);
		i_assert(size != 0);
	}

	if (!i_stream_try_alloc(stream, size, &avail))
		return -2;
	return 1;
}

static ssize_t i_stream_crlf_read_crlf(struct istream_private *stream)
{
	struct crlf_istream *cstream = (struct crlf_istream *)stream;
	const unsigned char *data, *ptr, *src, *src_end;
	unsigned char *dest, *dest_end;
	size_t size, copy_len;
	ssize_t ret;

	ret = i_stream_crlf_read_common(cstream);
	if (ret <= 0)
		return ret;

	/* at least one byte was read */
	data = i_stream_get_data(stream->parent, &size);

	dest = stream->w_buffer + stream->pos;
	dest_end = stream->w_buffer + stream->buffer_size;
	src = data;
	src_end = data + size;

	/* @UNSAFE: add missing CRs */
	if (*src == '\n') {
		if (!cstream->last_cr && dest < dest_end)
			*dest++ = '\r';

		if (dest < dest_end) {
			*dest++ = '\n';
			src++;
		}
	}

	while (dest < dest_end) {
		i_assert(src <= src_end);
		ptr = memchr(src, '\n', src_end - src);
		if (ptr == NULL)
			ptr = src_end;

		/* copy data up to LF */
		copy_len = ptr - src;
		if (dest + copy_len > dest_end)
			copy_len = dest_end - dest;

		if (copy_len > 0) {
			memcpy(dest, src, copy_len);

			dest += copy_len;
			src += copy_len;
		}

		i_assert(dest <= dest_end && src <= src_end);
		if (dest == dest_end || src == src_end)
			break;

		/* add the CR if necessary and copy the LF.
		   (src >= data+1, because data[0]=='\n' was
		   handled before this loop) */
		if (src[-1] != '\r')
			*dest++ = '\r';

		if (dest == dest_end)
			break;

		*dest++ = '\n';
		src++;
		i_assert(src == ptr + 1);
	}

	i_assert(dest != stream->w_buffer);
 	cstream->last_cr = dest[-1] == '\r';
	i_stream_skip(stream->parent, src - data);

	ret = (dest - stream->w_buffer) - stream->pos;
	i_assert(ret > 0);
	stream->pos = dest - stream->w_buffer;
	return ret;
}

static ssize_t i_stream_crlf_read_lf(struct istream_private *stream)
{
	struct crlf_istream *cstream = (struct crlf_istream *)stream;
	const unsigned char *data, *p;
	size_t i, dest, size, max;
	ssize_t ret;
	bool pending_cr;

	ret = i_stream_crlf_read_common(cstream);
	if (ret <= 0)
		return ret;

	data = i_stream_get_data(stream->parent, &size);

	/* @UNSAFE */
	/* \r\n -> \n
	   \r<anything> -> \r<anything>
	   \r\r\n -> \r\n */
	dest = stream->pos;
	pending_cr = cstream->pending_cr;
	for (i = 0; i < size && dest < stream->buffer_size; ) {
		if (data[i] == '\r') {
			if (pending_cr) {
				/* \r\r */
				stream->w_buffer[dest++] = '\r';
			} else {
				pending_cr = TRUE;
			}
			i++;
		} else if (data[i] == '\n') {
			/* [\r]\n */
			pending_cr = FALSE;
			stream->w_buffer[dest++] = '\n';
			i++;
		} else if (pending_cr) {
			/* \r<anything> */
			pending_cr = FALSE;
			stream->w_buffer[dest++] = '\r';
		} else {
			/* copy everything until the next \r */
			max = I_MIN(size - i, stream->buffer_size - dest);
			p = memchr(data + i, '\r', max);
			if (p != NULL)
				max = p - (data+i);
			memcpy(stream->w_buffer + dest, data + i, max);
			dest += max;
			i += max;
		}
	}
	i_assert(i <= size);
	i_assert(dest <= stream->buffer_size);

	cstream->pending_cr = pending_cr;
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

static struct istream *
i_stream_create_crlf_full(struct istream *input, bool crlf)
{
	struct crlf_istream *cstream;

	cstream = i_new(struct crlf_istream, 1);
	cstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	cstream->istream.read = crlf ? i_stream_crlf_read_crlf :
		i_stream_crlf_read_lf;

	cstream->istream.istream.readable_fd = FALSE;
	cstream->istream.istream.blocking = input->blocking;
	cstream->istream.istream.seekable = FALSE;
	return i_stream_create(&cstream->istream, input,
			       i_stream_get_fd(input), 0);
}

struct istream *i_stream_create_crlf(struct istream *input)
{
	return i_stream_create_crlf_full(input, TRUE);
}

struct istream *i_stream_create_lf(struct istream *input)
{
	return i_stream_create_crlf_full(input, FALSE);
}
