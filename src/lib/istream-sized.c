/* Copyright (c) 2003-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "istream-sized.h"

struct sized_istream {
	struct istream_private istream;

	uoff_t size;
};

static ssize_t i_stream_sized_read(struct istream_private *stream)
{
	struct sized_istream *sstream =
		(struct sized_istream *)stream;
	uoff_t left;
	ssize_t ret;
	size_t pos;

	if (stream->istream.v_offset +
	    (stream->pos - stream->skip) >= sstream->size) {
		stream->istream.eof = TRUE;
		return -1;
	}

	i_stream_seek(stream->parent, sstream->istream.parent_start_offset +
		      stream->istream.v_offset);

	stream->pos -= stream->skip;
	stream->skip = 0;

	stream->buffer = i_stream_get_data(stream->parent, &pos);
	if (pos > stream->pos)
		ret = 0;
	else do {
		if ((ret = i_stream_read(stream->parent)) == -2)
			return -2;

		stream->istream.stream_errno = stream->parent->stream_errno;
		stream->istream.eof = stream->parent->eof;
		stream->buffer = i_stream_get_data(stream->parent, &pos);
	} while (pos <= stream->pos && ret > 0);

	left = sstream->size - stream->istream.v_offset;
	if (pos == left)
		stream->istream.eof = TRUE;
	else if (pos > left) {
		i_error("%s is larger than expected (%"PRIuUOFF_T")",
			i_stream_get_name(stream->parent), sstream->size);
		pos = left;
		stream->istream.eof = TRUE;
	} else if (!stream->istream.eof) {
		/* still more to read */
	} else if (stream->istream.stream_errno == ENOENT) {
		/* lost the file */
	} else {
		i_error("%s smaller than expected "
			"(%"PRIuUOFF_T" < %"PRIuUOFF_T")",
			i_stream_get_name(stream->parent),
			stream->istream.v_offset, sstream->size);
		stream->istream.stream_errno = EINVAL;
	}

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = pos;
	i_assert(ret != -1 || stream->istream.eof ||
		 stream->istream.stream_errno != 0);
	return ret;
}

static int
i_stream_sized_stat(struct istream_private *stream, bool exact ATTR_UNUSED)
{
	struct sized_istream *sstream = (struct sized_istream *)stream;
	const struct stat *st;

	/* parent stream may be base64-decoder. don't waste time decoding the
	   entire stream, since we already know what the size is supposed
	   to be. */
	if (i_stream_stat(stream->parent, FALSE, &st) < 0)
		return -1;

	stream->statbuf = *st;
	stream->statbuf.st_size = sstream->size;
	return 0;
}

struct istream *i_stream_create_sized(struct istream *input, uoff_t size)
{
	struct sized_istream *sstream;

	sstream = i_new(struct sized_istream, 1);
	sstream->size = size;
	sstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	sstream->istream.read = i_stream_sized_read;
	sstream->istream.stat = i_stream_sized_stat;

	sstream->istream.istream.readable_fd = input->readable_fd;
	sstream->istream.istream.blocking = input->blocking;
	sstream->istream.istream.seekable = input->seekable;
	return i_stream_create(&sstream->istream, input,
			       i_stream_get_fd(input));
}
