/*
   ibuffer-data.c : Input buffer interface for reading from data buffer

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
#include "ibuffer-internal.h"

static void _close(_IOBuffer *buf __attr_unused__)
{
}

static void _destroy(_IOBuffer *buf __attr_unused__)
{
}

static void _set_max_size(_IOBuffer *buf __attr_unused__,
			  size_t max_size __attr_unused__)
{
}

static void _set_blocking(_IOBuffer *buf __attr_unused__,
			  int timeout_msecs __attr_unused__,
			  TimeoutFunc timeout_func __attr_unused__,
			  void *context __attr_unused__)
{
}

static ssize_t _read(_IBuffer *buf)
{
	return buf->pos - buf->skip;
}

static int _seek(_IBuffer *buf, uoff_t v_offset)
{
	buf->skip = v_offset;
	buf->ibuffer.v_offset = v_offset;
	return 1;
}

static void _skip(_IBuffer *buf, uoff_t count)
{
	buf->skip += count;
	buf->ibuffer.v_offset += count;
}

IBuffer *i_buffer_create_from_data(Pool pool, const unsigned char *data,
				   size_t size)
{
	_IBuffer *buf;

	buf = p_new(pool, _IBuffer, 1);
	buf->buffer = data;
	buf->pos = size;

	buf->iobuf.close = _close;
	buf->iobuf.destroy = _destroy;
	buf->iobuf.set_max_size = _set_max_size;
	buf->iobuf.set_blocking = _set_blocking;

	buf->read = _read;
	buf->skip_count = _skip;
	buf->seek = _seek;

	return _i_buffer_create(buf, pool, -1, 0, size);
}
