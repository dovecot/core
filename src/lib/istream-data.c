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

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	stream->skip = v_offset;
	stream->istream.v_offset = v_offset;
}

static uoff_t _get_size(struct _istream *stream)
{
	return stream->pos;
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
	stream->get_size = _get_size;

	return _i_stream_create(stream, pool, -1, 0);
}
