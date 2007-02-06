/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "istream-internal.h"

static void _close(struct _iostream *stream __attr_unused__)
{
}

static void _destroy(struct _iostream *stream __attr_unused__)
{
}

static void _set_max_buffer_size(struct _iostream *stream __attr_unused__,
				 size_t max_size __attr_unused__)
{
}

static ssize_t _read(struct _istream *stream __attr_unused__)
{
	stream->istream.eof = TRUE;
	return -1;
}

static void _seek(struct _istream *stream, uoff_t v_offset,
		  bool mark __attr_unused__)
{
	stream->skip = v_offset;
	stream->istream.v_offset = v_offset;
}

static const struct stat *
_stat(struct _istream *stream, bool exact __attr_unused__)
{
	stream->statbuf.st_size = stream->pos;
	return &stream->statbuf;
}

struct istream *i_stream_create_from_data(pool_t pool, const void *data,
					  size_t size)
{
	struct _istream *stream;

	stream = p_new(pool, struct _istream, 1);
	stream->buffer = data;
	stream->pos = size;

	stream->iostream.close = _close;
	stream->iostream.destroy = _destroy;
	stream->iostream.set_max_buffer_size = _set_max_buffer_size;

	stream->read = _read;
	stream->seek = _seek;
	stream->stat = _stat;

	stream->istream.blocking = TRUE;
	stream->istream.seekable = TRUE;
	return _i_stream_create(stream, pool, -1, 0);
}
