/*
   istream-data.c : Input stream interface for reading from data buffer

    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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

static void _set_blocking(struct _iostream *stream __attr_unused__,
			  int timeout_msecs __attr_unused__,
			  void (*timeout_cb)(void *) __attr_unused__,
			  void *context __attr_unused__)
{
}

static ssize_t _read(struct _istream *stream __attr_unused__)
{
	return -1;
}

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	stream->skip = v_offset;
	stream->istream.v_offset = v_offset;
}

static void _skip(struct _istream *stream, uoff_t count)
{
	stream->skip += count;
	stream->istream.v_offset += count;
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
	stream->iostream.set_blocking = _set_blocking;

	stream->read = _read;
	stream->skip_count = _skip;
	stream->seek = _seek;

	return _i_stream_create(stream, pool, -1, 0, size);
}
