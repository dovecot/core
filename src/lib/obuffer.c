/*
   obuffer.c : Output buffer handling

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
#include "ibuffer.h"
#include "obuffer-internal.h"

void o_buffer_ref(OBuffer *buf)
{
	_io_buffer_ref(buf->real_buffer);
}

void o_buffer_unref(OBuffer *buf)
{
	_io_buffer_unref(buf->real_buffer);
}

void o_buffer_close(OBuffer *buf)
{
	_io_buffer_close(buf->real_buffer);
	buf->closed = TRUE;
}

void o_buffer_set_max_size(OBuffer *buf, size_t max_size)
{
	_io_buffer_set_max_size(buf->real_buffer, max_size);
}

void o_buffer_set_blocking(OBuffer *buf, int timeout_msecs,
			   void (*timeout_func)(void *), void *context)
{
	_io_buffer_set_blocking(buf->real_buffer, timeout_msecs,
				timeout_func, context);
}

void o_buffer_cork(OBuffer *buf)
{
	_OBuffer *_buf = buf->real_buffer;

	if (buf->closed)
		return;

	_buf->cork(_buf);
}

int o_buffer_flush(OBuffer *buf)
{
	_OBuffer *_buf = buf->real_buffer;

	if (buf->closed)
		return -1;

	return _buf->flush(_buf);
}

int o_buffer_have_space(OBuffer *buf, size_t size)
{
	_OBuffer *_buf = buf->real_buffer;

	return _buf->have_space(_buf, size);
}

int o_buffer_seek(OBuffer *buf, uoff_t offset)
{
	_OBuffer *_buf = buf->real_buffer;

	if (buf->closed)
		return -1;

	return _buf->seek(_buf, offset);
}

ssize_t o_buffer_send(OBuffer *buf, const void *data, size_t size)
{
	_OBuffer *_buf = buf->real_buffer;

	if (buf->closed)
		return -1;

	if (size == 0)
		return 0;

	return _buf->send(_buf, data, size);
}

off_t o_buffer_send_ibuffer(OBuffer *outbuf, IBuffer *inbuf)
{
	_OBuffer *_outbuf = outbuf->real_buffer;

	if (outbuf->closed || inbuf->closed)
		return -1;

	return _outbuf->send_ibuffer(_outbuf, inbuf);
}

OBuffer *_o_buffer_create(_OBuffer *_buf, Pool pool)
{
	_buf->obuffer.real_buffer = _buf;

	_io_buffer_init(pool, &_buf->iobuf);
	return &_buf->obuffer;
}
