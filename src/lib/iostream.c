/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
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

bool io_stream_unref(struct iostream_private *stream)
{
	i_assert(stream->refcount > 0);
	if (--stream->refcount != 0)
		return TRUE;

	stream->close(stream, FALSE);
	stream->destroy(stream);
	return FALSE;
}

void io_stream_free(struct iostream_private *stream)
{
	const struct iostream_destroy_callback *dc;

	if (array_is_created(&stream->destroy_callbacks)) {
		array_foreach(&stream->destroy_callbacks, dc)
			dc->callback(dc->context);
		array_free(&stream->destroy_callbacks);
	}

        i_free(stream->error);
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

void io_stream_add_destroy_callback(struct iostream_private *stream,
				    void (*callback)(void *), void *context)
{
	struct iostream_destroy_callback *dc;

	if (!array_is_created(&stream->destroy_callbacks))
		i_array_init(&stream->destroy_callbacks, 2);
	dc = array_append_space(&stream->destroy_callbacks);
	dc->callback = callback;
	dc->context = context;
}

void io_stream_remove_destroy_callback(struct iostream_private *stream,
				       void (*callback)(void *))
{
	const struct iostream_destroy_callback *dcs;
	unsigned int i, count;

	dcs = array_get(&stream->destroy_callbacks, &count);
	for (i = 0; i < count; i++) {
		if (dcs[i].callback == callback) {
			array_delete(&stream->destroy_callbacks, i, 1);
			return;
		}
	}
	i_unreached();
}

void io_stream_set_error(struct iostream_private *stream,
			 const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	io_stream_set_verror(stream, fmt, args);
	va_end(args);
}

void io_stream_set_verror(struct iostream_private *stream,
			  const char *fmt, va_list args)
{
	i_free(stream->error);
	stream->error = i_strdup_vprintf(fmt, args);
}

const char *io_stream_get_disconnect_reason(struct istream *input,
					    struct ostream *output)
{
	const char *errstr;

	if (input != NULL && input->stream_errno != 0) {
		errno = input->stream_errno;
		errstr = i_stream_get_error(input);
	} else if (output != NULL && output->stream_errno != 0) {
		errno = output->stream_errno;
		errstr = o_stream_get_error(output);
	} else {
		errno = 0;
		errstr = "";
	}

	if (errno == 0 || errno == EPIPE)
		return "Connection closed";
	else
		return t_strdup_printf("Connection closed: %s", errstr);
}
