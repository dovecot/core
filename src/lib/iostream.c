/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "iostream-private.h"

static void
io_stream_default_close(struct iostream_private *stream ATTR_UNUSED,
			bool close_parent ATTR_UNUSED)
{
}

static void
io_stream_default_destroy(struct iostream_private *stream ATTR_UNUSED)
{
}

void io_stream_init(struct iostream_private *stream)
{
	if (stream->close == NULL)
		stream->close = io_stream_default_close;
	if (stream->destroy == NULL)
		stream->destroy = io_stream_default_destroy;

	stream->refcount = 1;
}

void io_stream_ref(struct iostream_private *stream)
{
	stream->refcount++;
}

void io_stream_unref(struct iostream_private *stream)
{
	const struct iostream_destroy_callback *dc;

	i_assert(stream->refcount > 0);
	if (--stream->refcount != 0)
		return;

	stream->close(stream, FALSE);
	stream->destroy(stream);
	if (array_is_created(&stream->destroy_callbacks)) {
		array_foreach(&stream->destroy_callbacks, dc)
			dc->callback(dc->context);
		array_free(&stream->destroy_callbacks);
	}

        i_free(stream->name);
        i_free(stream);
}

void io_stream_close(struct iostream_private *stream, bool close_parent)
{
	stream->close(stream, close_parent);
}

void io_stream_set_max_buffer_size(struct iostream_private *stream,
				   size_t max_size)
{
	stream->set_max_buffer_size(stream, max_size);
}
