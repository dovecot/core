/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "istream-internal.h"

static void _close(struct iostream_private *stream ATTR_UNUSED)
{
}

static void _destroy(struct iostream_private *stream ATTR_UNUSED)
{
}

static ssize_t _read(struct istream_private *stream ATTR_UNUSED)
{
	stream->istream.eof = TRUE;
	return -1;
}

static void _seek(struct istream_private *stream, uoff_t v_offset,
		  bool mark ATTR_UNUSED)
{
	stream->skip = v_offset;
	stream->istream.v_offset = v_offset;
}

struct istream *i_stream_create_from_data(const void *data, size_t size)
{
	struct istream_private *stream;

	stream = i_new(struct istream_private, 1);
	stream->buffer = data;
	stream->pos = size;

	stream->iostream.close = _close;
	stream->iostream.destroy = _destroy;

	stream->read = _read;
	stream->seek = _seek;

	stream->istream.blocking = TRUE;
	stream->istream.seekable = TRUE;
	(void)i_stream_create(stream, -1, 0);
	stream->statbuf.st_size = size;
	return &stream->istream;
}
