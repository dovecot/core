/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "qp-decoder.h"
#include "istream-private.h"
#include "istream-qp.h"

struct qp_decoder_istream {
	struct istream_private istream;
	buffer_t *buf;
	struct qp_decoder *qp;
};

static void i_stream_qp_decoder_close(struct iostream_private *stream,
				      bool close_parent)
{
	struct qp_decoder_istream *bstream =
		(struct qp_decoder_istream *)stream;

	if (bstream->qp != NULL)
		qp_decoder_deinit(&bstream->qp);
	if (bstream->buf != NULL)
		buffer_free(&bstream->buf);
	if (close_parent)
		i_stream_close(bstream->istream.parent);
}

static ssize_t i_stream_qp_decoder_read(struct istream_private *stream)
{
	struct qp_decoder_istream *bstream =
		(struct qp_decoder_istream *)stream;
	const unsigned char *data;
	size_t size, avail, error_pos;
	const char *error;
	int ret;

	for (;;) {
		/* if something is already decoded, return as much of it as
		   we can */
		if (bstream->buf->used > 0) {
			i_stream_try_alloc(stream, bstream->buf->used, &avail);
			if (avail == 0)
				return -2;
			size = I_MIN(avail, bstream->buf->used);
			memcpy(stream->w_buffer + stream->pos,
			       bstream->buf->data, size);
			buffer_delete(bstream->buf, 0, size);
			stream->pos += size;
			return size;
		}
		/* need to read more input */
		ret = i_stream_read_data(stream->parent, &data, &size, 0);
		if (ret <= 0) {
			stream->istream.stream_errno = stream->parent->stream_errno;
			stream->istream.eof = stream->parent->eof;
			if (ret != -1 || stream->istream.stream_errno != 0)
				return ret;
			/* end of quoted-printable stream. verify that the
			   ending is ok. */
			if (qp_decoder_finish(bstream->qp, &error) == 0) {
				i_assert(bstream->buf->used == 0);
				return -1;
			}
			io_stream_set_error(&stream->iostream,
				"Invalid quoted-printable input trailer: %s", error);
			stream->istream.stream_errno = EINVAL;
			return -1;
		}
		if (qp_decoder_more(bstream->qp, data, size,
				    &error_pos, &error) < 0) {
			i_assert(error_pos < size);
			io_stream_set_error(&stream->iostream,
				"Invalid quoted-printable input 0x%s: %s",
				binary_to_hex(data+error_pos, I_MIN(size-error_pos, 8)), error);
			stream->istream.stream_errno = EINVAL;
			return -1;
		}
		i_stream_skip(stream->parent, size);
	}
}

static void
i_stream_qp_decoder_seek(struct istream_private *stream,
			     uoff_t v_offset, bool mark)
{
	struct qp_decoder_istream *bstream =
		(struct qp_decoder_istream *)stream;
	const char *error;

	if (v_offset < stream->istream.v_offset) {
		/* seeking backwards - go back to beginning and seek
		   forward from there. */
		stream->parent_expected_offset = stream->parent_start_offset;
		stream->skip = stream->pos = 0;
		stream->istream.v_offset = 0;
		i_stream_seek(stream->parent, 0);
		(void)qp_decoder_finish(bstream->qp, &error);
		buffer_set_used_size(bstream->buf, 0);
	}
	i_stream_default_seek_nonseekable(stream, v_offset, mark);
}

struct istream *i_stream_create_qp_decoder(struct istream *input)
{
	struct qp_decoder_istream *bstream;

	bstream = i_new(struct qp_decoder_istream, 1);
	bstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	bstream->buf = buffer_create_dynamic(default_pool, 128);
	bstream->qp = qp_decoder_init(bstream->buf);

	bstream->istream.iostream.close = i_stream_qp_decoder_close;
	bstream->istream.read = i_stream_qp_decoder_read;
	bstream->istream.seek = i_stream_qp_decoder_seek;

	bstream->istream.istream.readable_fd = FALSE;
	bstream->istream.istream.blocking = input->blocking;
	bstream->istream.istream.seekable = input->seekable;
	return i_stream_create(&bstream->istream, input,
			       i_stream_get_fd(input));
}
