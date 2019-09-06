/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"

struct limit_istream {
	struct istream_private istream;

	uoff_t v_size;
};

static void i_stream_limit_destroy(struct iostream_private *stream)
{
       struct limit_istream *lstream = (struct limit_istream *) stream;
       uoff_t v_offset;

       v_offset = lstream->istream.parent_start_offset +
               lstream->istream.istream.v_offset;
       if (lstream->istream.parent->seekable ||
           v_offset > lstream->istream.parent->v_offset) {
               /* get to same position in parent stream */
               i_stream_seek(lstream->istream.parent, v_offset);
       }
}

static ssize_t i_stream_limit_read(struct istream_private *stream)
{
	struct limit_istream *lstream = (struct limit_istream *) stream;
	uoff_t left;
	ssize_t ret;
	size_t pos;

	i_stream_seek(stream->parent, lstream->istream.parent_start_offset +
		      stream->istream.v_offset);

	if (stream->istream.v_offset +
	    (stream->pos - stream->skip) >= lstream->v_size) {
		stream->istream.eof = TRUE;
		return -1;
	}

	stream->pos -= stream->skip;
	stream->skip = 0;

	stream->buffer = i_stream_get_data(stream->parent, &pos);
	if (pos > stream->pos)
		ret = 0;
	else do {
		ret = i_stream_read_memarea(stream->parent);
		stream->istream.stream_errno = stream->parent->stream_errno;
		stream->istream.eof = stream->parent->eof;
		stream->buffer = i_stream_get_data(stream->parent, &pos);
	} while (pos <= stream->pos && ret > 0);
	if (ret == -2)
		return -2;

	if (lstream->v_size != (uoff_t)-1) {
		left = lstream->v_size - stream->istream.v_offset;
		if (pos >= left) {
			pos = left;
			stream->istream.eof = TRUE;
		}
	}

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = pos;
	i_assert(ret != -1 || stream->istream.eof ||
		 stream->istream.stream_errno != 0);
	return ret;
}

static int
i_stream_limit_stat(struct istream_private *stream, bool exact)
{
	struct limit_istream *lstream = (struct limit_istream *) stream;
	const struct stat *st;

	if (i_stream_stat(stream->parent, exact, &st) < 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		return -1;
	}

	stream->statbuf = *st;
	if (lstream->v_size != (uoff_t)-1)
		stream->statbuf.st_size = lstream->v_size;
	return 0;
}

static int i_stream_limit_get_size(struct istream_private *stream,
				   bool exact, uoff_t *size_r)
{
	struct limit_istream *lstream = (struct limit_istream *) stream;
	const struct stat *st;

	if (lstream->v_size != (uoff_t)-1) {
		*size_r = lstream->v_size;
		return 1;
	}

	if (i_stream_stat(&stream->istream, exact, &st) < 0)
		return -1;
	if (st->st_size == -1)
		return 0;

	*size_r = st->st_size;
	return 1;
}

struct istream *i_stream_create_limit(struct istream *input, uoff_t v_size)
{
	struct limit_istream *lstream;

	lstream = i_new(struct limit_istream, 1);
	lstream->v_size = v_size;
	lstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	lstream->istream.iostream.destroy = i_stream_limit_destroy;
	lstream->istream.read = i_stream_limit_read;
	lstream->istream.stat = i_stream_limit_stat;
	lstream->istream.get_size = i_stream_limit_get_size;

	lstream->istream.istream.readable_fd = input->readable_fd;
	lstream->istream.istream.blocking = input->blocking;
	lstream->istream.istream.seekable = input->seekable;
	return i_stream_create(&lstream->istream, input,
			       i_stream_get_fd(input), 0);
}

struct istream *i_stream_create_range(struct istream *input,
				      uoff_t v_offset, uoff_t v_size)
{
	uoff_t orig_offset = input->v_offset;
	struct istream *ret;

	input->v_offset = v_offset;
	ret = i_stream_create_limit(input, v_size);
	input->v_offset = orig_offset;
	return ret;
}
