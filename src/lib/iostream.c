/*
   iostream.c : Input/output stream common handling

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
#include "iostream-internal.h"

void _io_stream_init(pool_t pool, struct _iostream *stream)
{
	stream->pool = pool;
	stream->refcount = 1;
}

void _io_stream_ref(struct _iostream *stream)
{
	stream->refcount++;
}

void _io_stream_unref(struct _iostream *stream)
{
	pool_t pool;

	i_assert(stream->refcount > 0);
	if (--stream->refcount != 0)
		return;

	stream->close(stream);
	stream->destroy(stream);

	pool = stream->pool;
        p_free(pool, stream);
	pool_unref(pool);
}

void _io_stream_close(struct _iostream *stream)
{
	stream->close(stream);
}

void _io_stream_set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	stream->set_max_buffer_size(stream, max_size);
}

void _io_stream_set_blocking(struct _iostream *stream, int timeout_msecs,
			     void (*timeout_cb)(void *), void *context)
{
	stream->set_blocking(stream, timeout_msecs, timeout_cb, context);
}
