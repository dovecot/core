/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "message-parser.h"
#include "istream-internal.h"
#include "mbox-index.h"

struct mbox_istream {
	struct _istream istream;

	struct istream *input;

	buffer_t *headers;
	uoff_t v_header_size, body_offset, body_size;
};

static void _close(struct _iostream *stream __attr_unused__)
{
}

static void _destroy(struct _iostream *stream)
{
	struct mbox_istream *mstream = (struct mbox_istream *) stream;

	i_stream_unref(mstream->input);
	buffer_free(mstream->headers);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct mbox_istream *mstream = (struct mbox_istream *) stream;

	i_stream_set_max_buffer_size(mstream->input, max_size);
}

static void _set_blocking(struct _iostream *stream, int timeout_msecs,
			  void (*timeout_cb)(void *), void *context)
{
	struct mbox_istream *mstream = (struct mbox_istream *) stream;

	i_stream_set_blocking(mstream->input, timeout_msecs,
			      timeout_cb, context);
}

static ssize_t _read(struct _istream *stream)
{
	struct mbox_istream *mstream = (struct mbox_istream *) stream;
	ssize_t ret;
	size_t pos;
	uoff_t offset;

	if (stream->istream.v_offset < mstream->v_header_size) {
		/* we don't support mixing headers and body.
		   it shouldn't be needed. */
		return -2;
	}

	offset = stream->istream.v_offset - mstream->v_header_size;
	if (mstream->input->v_offset != offset)
		i_stream_seek(mstream->input, offset);

	ret = i_stream_read(mstream->input);

	stream->pos -= stream->skip;
	stream->skip = 0;
	stream->buffer = i_stream_get_data(mstream->input, &pos);

	ret = pos <= stream->pos ? -1 :
		(ssize_t) (pos - stream->pos);
	mstream->istream.pos = pos;
	return ret;
}

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	struct mbox_istream *mstream = (struct mbox_istream *) stream;

	stream->istream.v_offset = v_offset;
	if (v_offset < mstream->v_header_size) {
		/* still in headers */
		stream->skip = v_offset;
		stream->pos = mstream->v_header_size;
		stream->buffer = buffer_get_data(mstream->headers, NULL);
	} else {
		/* body - use our real input stream */
		stream->skip = stream->pos = 0;
		stream->buffer = NULL;
	}
}

struct istream *i_stream_create_mbox(pool_t pool, struct istream *input,
				     uoff_t offset, uoff_t body_size)
{
	struct mbox_istream *mstream;
	struct istream *hdr_input;

	mstream = p_new(pool, struct mbox_istream, 1);
	mstream->body_size = body_size;

	if (body_size == 0) {
		/* possibly broken message, find the next From-line
		   and make sure header parser won't pass it. */
		mbox_skip_header(input);
		hdr_input = i_stream_create_limit(pool, input,
						  0, input->v_offset);
	} else {
		hdr_input = input;
		i_stream_ref(input);
	}

	mstream->headers = buffer_create_dynamic(default_pool,
						 8192, (size_t)-1);
	i_stream_seek(hdr_input, offset);
	mbox_read_headers(hdr_input, mstream->headers);
	mstream->v_header_size = buffer_get_used_size(mstream->headers);
	mstream->body_offset = hdr_input->v_offset;
	i_stream_unref(hdr_input);

	mstream->input = i_stream_create_limit(pool, input,
					       mstream->body_offset, body_size);

	mstream->istream.buffer = buffer_get_data(mstream->headers, NULL);
	mstream->istream.pos = mstream->v_header_size;

	mstream->istream.iostream.close = _close;
	mstream->istream.iostream.destroy = _destroy;
	mstream->istream.iostream.set_max_buffer_size = _set_max_buffer_size;
	mstream->istream.iostream.set_blocking = _set_blocking;

	mstream->istream.read = _read;
	mstream->istream.seek = _seek;

	return _i_stream_create(&mstream->istream, pool, -1,
				input->real_stream->abs_start_offset);
}
