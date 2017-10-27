/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "qp-encoder.h"
#include "istream-private.h"
#include "istream-qp.h"

struct qp_encoder_istream {
	struct istream_private istream;
	buffer_t *buf;
	struct qp_encoder *qp;
};

static void i_stream_qp_encoder_close(struct iostream_private *stream,
				      bool close_parent)
{
	struct qp_encoder_istream *bstream =
		(struct qp_encoder_istream *)stream;

	if (bstream->qp != NULL)
		qp_encoder_deinit(&bstream->qp);
	buffer_free(&bstream->buf);
	if (close_parent)
		i_stream_close(bstream->istream.parent);
}

static ssize_t i_stream_qp_encoder_read(struct istream_private *stream)
{
	struct qp_encoder_istream *bstream =
		(struct qp_encoder_istream *)stream;
	const unsigned char *data;
	size_t size;
	int ret;

	for(;;) {
		if (stream->skip > 0) {
			i_assert(stream->skip <= bstream->buf->used);
			buffer_delete(bstream->buf, 0, stream->skip);
			stream->pos -= stream->skip;
			stream->skip = 0;
		}

		stream->buffer = bstream->buf->data;
		i_assert(stream->pos <= bstream->buf->used);

		if (stream->pos >= bstream->istream.max_buffer_size) {
			/* stream buffer still at maximum */
			return -2;
		}

		/* if something is already interpolated, return as much of it as
		   we can */
		if (bstream->buf->used > 0) {
			size_t new_pos, bytes;

			/* only return up to max_buffer_size bytes, even when buffer
			   actually has more, as not to confuse the caller */
			if (bstream->buf->used <= bstream->istream.max_buffer_size) {
				new_pos = bstream->buf->used;
				if (stream->parent->eof)
					stream->istream.eof = TRUE;
			} else {
				new_pos = bstream->istream.max_buffer_size;
			}

			bytes = new_pos - stream->pos;
			stream->pos = new_pos;
			return (ssize_t)bytes;
		}

		/* need to read more input */
		ret = i_stream_read_more(stream->parent, &data, &size);
		if (ret == 0)
			return ret;
		if (size == 0 && ret == -1) {
			stream->istream.stream_errno =
				stream->parent->stream_errno;
			stream->istream.eof = stream->parent->eof;
			return ret;
		}
		qp_encoder_more(bstream->qp, data, size);
		i_stream_skip(stream->parent, size);
	}
}

static void
i_stream_qp_encoder_seek(struct istream_private *stream,
			     uoff_t v_offset, bool mark)
{
	struct qp_encoder_istream *bstream =
		(struct qp_encoder_istream *)stream;

	if (v_offset < stream->istream.v_offset) {
		/* seeking backwards - go back to beginning and seek
		   forward from there. */
		stream->parent_expected_offset = stream->parent_start_offset;
		stream->skip = stream->pos = 0;
		stream->istream.v_offset = 0;
		i_stream_seek(stream->parent, 0);
		qp_encoder_finish(bstream->qp);
		buffer_set_used_size(bstream->buf, 0);
	}
	i_stream_default_seek_nonseekable(stream, v_offset, mark);
}

struct istream *i_stream_create_qp_encoder(struct istream *input,
					   enum qp_encoder_flag flags)
{
	struct qp_encoder_istream *bstream;

	bstream = i_new(struct qp_encoder_istream, 1);
	bstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	bstream->buf = buffer_create_dynamic(default_pool, 128);
	bstream->qp = qp_encoder_init(bstream->buf, ISTREAM_QP_ENCODER_MAX_LINE_LENGTH, flags);

	bstream->istream.iostream.close = i_stream_qp_encoder_close;
	bstream->istream.read = i_stream_qp_encoder_read;
	bstream->istream.seek = i_stream_qp_encoder_seek;

	bstream->istream.istream.readable_fd = FALSE;
	bstream->istream.istream.blocking = input->blocking;
	bstream->istream.istream.seekable = input->seekable;
	return i_stream_create(&bstream->istream, input,
			       i_stream_get_fd(input), 0);
}
