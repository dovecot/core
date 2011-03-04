/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "iostream-internal.h"

static void
io_stream_default_close_destroy(struct iostream_private *stream ATTR_UNUSED)
{
}

void io_stream_init(struct iostream_private *stream)
{
	if (stream->close == NULL)
		stream->close = io_stream_default_close_destroy;
	if (stream->destroy == NULL)
		stream->destroy = io_stream_default_close_destroy;

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
	if (stream->destroy_callback != NULL)
		stream->destroy_callback(stream->destroy_context);

        i_free(stream->name);
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
