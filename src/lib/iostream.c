/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "iostream-internal.h"

void _io_stream_init(pool_t pool, struct _iostream *stream)
{
	pool_ref(pool);
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
