/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"

static ssize_t i_stream_data_read(struct istream_private *stream)
{
	stream->istream.eof = TRUE;
	return -1;
}

static void i_stream_data_seek(struct istream_private *stream, uoff_t v_offset,
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

	stream->read = i_stream_data_read;
	stream->seek = i_stream_data_seek;

	stream->istream.readable_fd = FALSE;
	stream->istream.blocking = TRUE;
	stream->istream.seekable = TRUE;
	(void)i_stream_create(stream, NULL, -1);
	stream->statbuf.st_size = size;
	return &stream->istream;
}
