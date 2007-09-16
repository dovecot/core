/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "iostream-internal.h"

void io_stream_init(struct iostream_private *stream)
{
	stream->refcount = 1;
}

void io_stream_ref(struct iostream_private *stream)
{
	stream->refcount++;
}

void io_stream_unref(struct iostream_private *stream)
{
	i_assert(stream->refcount > 0);
	if (--stream->refcount != 0)
		return;

	stream->close(stream);
	stream->destroy(stream);

        i_free(stream);
}

void io_stream_close(struct iostream_private *stream)
{
	stream->close(stream);
}

void io_stream_set_max_buffer_size(struct iostream_private *stream,
				   size_t max_size)
{
	stream->set_max_buffer_size(stream, max_size);
}
