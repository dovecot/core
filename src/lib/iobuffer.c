/*
   iobuffer.c : Input/output buffer common handling

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
#include "iobuffer-internal.h"

void _io_buffer_init(Pool pool, _IOBuffer *buf)
{
	buf->pool = pool;
	buf->refcount = 1;
}

void _io_buffer_ref(_IOBuffer *buf)
{
	buf->refcount++;
}

void _io_buffer_unref(_IOBuffer *buf)
{
	Pool pool;

	i_assert(buf->refcount > 0);
	if (--buf->refcount != 0)
		return;

	buf->close(buf);
	buf->destroy(buf);

	pool = buf->pool;
        p_free(pool, buf);
	pool_unref(pool);
}

void _io_buffer_close(_IOBuffer *buf)
{
	buf->close(buf);
}

void _io_buffer_set_max_size(_IOBuffer *buf, size_t max_size)
{
	buf->set_max_size(buf, max_size);
}

void _io_buffer_set_blocking(_IOBuffer *buf, int timeout_msecs,
			     void (*timeout_func)(void *), void *context)
{
	buf->set_blocking(buf, timeout_msecs, timeout_func, context);
}
