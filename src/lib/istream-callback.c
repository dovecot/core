/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream-private.h"
#include "istream-callback.h"

struct callback_istream {
	struct istream_private istream;
	istream_callback_read_t *callback;
	void *context;

	buffer_t *buf;
	size_t prev_pos;
};

static void i_stream_callback_destroy(struct iostream_private *stream)
{
	struct callback_istream *cstream = (struct callback_istream *)stream;

	buffer_free(&cstream->buf);
}

static ssize_t i_stream_callback_read(struct istream_private *stream)
{
	struct callback_istream *cstream = (struct callback_istream *)stream;
	size_t pos;

	if (cstream->callback == NULL) {
		/* already returned EOF / error */
		stream->istream.eof = TRUE;
		return -1;
	}

	if (stream->skip > 0) {
		buffer_delete(cstream->buf, 0, stream->skip);
		stream->pos -= stream->skip;
		cstream->prev_pos -= stream->skip;
		stream->skip = 0;
	}
	i_assert(cstream->buf->used >= cstream->prev_pos);
	pos = cstream->prev_pos;
	if (cstream->buf->used > pos) {
		/* data was added outside the callback */
	} else if (!cstream->callback(cstream->buf, cstream->context)) {
		/* EOF / error */
		stream->istream.eof = TRUE;
		cstream->callback = NULL;
		if (cstream->buf->used == pos ||
		    stream->istream.stream_errno != 0)
			return -1;
		/* EOF was returned with some data still added to the buffer.
		   return the buffer first and EOF only on the next call. */
	} else if (cstream->buf->used == pos) {
		/* buffer full */
		i_assert(cstream->buf->used > 0);
		return -2;
	}
	i_assert(cstream->buf->used > pos);
	stream->buffer = cstream->buf->data;
	cstream->prev_pos = stream->pos = cstream->buf->used;
	return cstream->buf->used - pos;
}

#undef i_stream_create_callback
struct istream *
i_stream_create_callback(istream_callback_read_t *callback, void *context)
{
	struct callback_istream *cstream;
	struct istream *istream;

	i_assert(callback != NULL);

	cstream = i_new(struct callback_istream, 1);
	cstream->callback = callback;
	cstream->context = context;
	cstream->buf = buffer_create_dynamic(default_pool, 1024);

	cstream->istream.iostream.destroy = i_stream_callback_destroy;
	cstream->istream.read = i_stream_callback_read;

	istream = i_stream_create(&cstream->istream, NULL, -1);
	istream->blocking = TRUE;
	return istream;
}

void i_stream_callback_append(struct istream *input,
			      const void *data, size_t size)
{
	struct callback_istream *cstream =
		(struct callback_istream *)input->real_stream;

	buffer_append(cstream->buf, data, size);
}

void i_stream_callback_append_str(struct istream *input, const char *str)
{
	i_stream_callback_append(input, str, strlen(str));
}

buffer_t *i_stream_callback_get_buffer(struct istream *input)
{
	struct callback_istream *cstream =
		(struct callback_istream *)input->real_stream;

	return cstream->buf;
}

void i_stream_callback_set_error(struct istream *input, int stream_errno,
				 const char *error)
{
	input->stream_errno = stream_errno;
	io_stream_set_error(&input->real_stream->iostream, "%s", error);
}
