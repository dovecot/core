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
	uoff_t body_offset, body_size;
	struct message_size header_size;
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
	uoff_t limit, old_limit;
	off_t vsize_diff;

	if (stream->istream.v_offset < mstream->header_size.virtual_size) {
		/* we don't support mixing headers and body.
		   it shouldn't be needed. */
		return -2;
	}

	/* may be positive or negative, depending on how much there was CRs
	   and how much headers were hidden */
	vsize_diff = mstream->header_size.virtual_size -
		mstream->header_size.physical_size;

	limit = stream->istream.v_limit - vsize_diff;
	old_limit = mstream->input->v_limit;
	if (limit != old_limit)
		i_stream_set_read_limit(mstream->input, limit);

	if (mstream->input->v_offset != stream->istream.v_offset - vsize_diff) {
		i_stream_seek(mstream->input,
			      stream->istream.v_offset - vsize_diff);
	}

	ret = i_stream_read(mstream->input);

	mstream->istream.pos -= mstream->istream.skip;
	mstream->istream.skip = 0;
	mstream->istream.buffer = i_stream_get_data(mstream->input, &pos);

	ret = pos <= mstream->istream.pos ? -1 :
		(ssize_t) (pos - mstream->istream.pos);
	mstream->istream.pos = pos;

	if (limit != old_limit)
		i_stream_set_read_limit(mstream->input, old_limit);
	return ret;
}

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	struct mbox_istream *mstream = (struct mbox_istream *) stream;

	stream->istream.v_offset = v_offset;
	if (v_offset < mstream->header_size.virtual_size) {
		/* still in headers */
		stream->skip = v_offset;
		stream->pos = stream->high_pos =
			mstream->header_size.virtual_size;
		stream->buffer = buffer_get_data(mstream->headers, NULL);
	} else {
		/* body - use our real input stream */
		stream->skip = stream->pos = stream->high_pos = 0;
		stream->buffer = NULL;

		v_offset += (off_t)mstream->header_size.physical_size -
			(off_t)mstream->header_size.virtual_size;
		i_stream_seek(mstream->input, v_offset);
	}
}

static void _skip(struct _istream *stream, uoff_t count)
{
	i_stream_seek(&stream->istream, stream->istream.v_offset + count);
}

struct istream *i_stream_create_mbox(pool_t pool, struct istream *input,
				     uoff_t body_size)
{
	struct mbox_istream *mstream;

	mstream = p_new(pool, struct mbox_istream, 1);
	mstream->input = input;
	mstream->body_size = body_size;

	if (body_size == 0) {
		/* possibly broken message, find the next From-line
		   and make sure header parser won't pass it. */
		mbox_skip_header(input);
		i_stream_set_read_limit(input, input->v_offset);
		i_stream_seek(input, 0);
	}

	mstream->headers = buffer_create_dynamic(default_pool,
						 8192, (size_t)-1);
	mbox_hide_headers(input, mstream->headers,
			  &mstream->header_size);
	mstream->body_offset = input->v_offset;
	i_stream_set_read_limit(input, mstream->body_offset + body_size);

	mstream->istream.buffer = buffer_get_data(mstream->headers, NULL);
	mstream->istream.pos = mstream->header_size.virtual_size;

	mstream->istream.iostream.close = _close;
	mstream->istream.iostream.destroy = _destroy;
	mstream->istream.iostream.set_max_buffer_size = _set_max_buffer_size;
	mstream->istream.iostream.set_blocking = _set_blocking;

	mstream->istream.read = _read;
	mstream->istream.skip_count = _skip;
	mstream->istream.seek = _seek;

	return _i_stream_create(&mstream->istream, pool, -1, 0,
				mstream->header_size.virtual_size + body_size);
}
