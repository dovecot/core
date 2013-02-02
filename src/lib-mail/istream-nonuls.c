/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "istream-nonuls.h"

struct nonuls_istream {
	struct istream_private istream;
	char replace_chr;
};

static int i_stream_read_parent(struct istream_private *stream)
{
	ssize_t ret;

	if (i_stream_get_data_size(stream->parent) > 0)
		return 1;

	ret = i_stream_read(stream->parent);
	if (ret <= 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		stream->istream.eof = stream->parent->eof;
		return ret;
	}
	i_assert(i_stream_get_data_size(stream->parent) != 0);
	return 1;
}

static ssize_t i_stream_nonuls_read(struct istream_private *stream)
{
	struct nonuls_istream *nstream = (struct nonuls_istream *)stream;
	const unsigned char *data, *p;
	size_t i, size, avail_size;
	int ret;

	if ((ret = i_stream_read_parent(stream)) <= 0)
		return ret;

	data = i_stream_get_data(stream->parent, &size);
	if (!i_stream_try_alloc(stream, size, &avail_size))
		return -2;
	if (size > avail_size)
		size = avail_size;
	i_assert(size > 0);

	p = memchr(data, '\0', size);
	if (p == NULL) {
		/* no NULs in this block */
		memcpy(stream->w_buffer+stream->pos, data, size);
	} else {
		i = p-data;
		memcpy(stream->w_buffer+stream->pos, data, i);
		for (; i < size; i++) {
			stream->w_buffer[stream->pos+i] = data[i] == '\0' ?
				nstream->replace_chr : data[i];
		}
	}
	stream->pos += size;
	i_stream_skip(stream->parent, size);
	return size;
}

struct istream *i_stream_create_nonuls(struct istream *input, char replace_chr)
{
	struct nonuls_istream *nstream;

	nstream = i_new(struct nonuls_istream, 1);
	nstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	nstream->istream.stream_size_passthrough = TRUE;

	nstream->istream.read = i_stream_nonuls_read;

	nstream->istream.istream.readable_fd = FALSE;
	nstream->istream.istream.blocking = input->blocking;
	nstream->istream.istream.seekable = FALSE;
	nstream->replace_chr = replace_chr;
	return i_stream_create(&nstream->istream, input,
			       i_stream_get_fd(input));
}
