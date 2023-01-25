/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ostream-private.h"
#include "ostream-final-trickle.h"

struct final_trickle_ostream {
	struct ostream_private ostream;
	struct timeout *to;

	unsigned char buffer_char;
	bool buffer_used;
};

static void
o_stream_final_trickle_close(struct iostream_private *stream, bool close_parent)
{
	struct final_trickle_ostream *dstream =
		container_of(stream, struct final_trickle_ostream,
			     ostream.iostream);

	timeout_remove(&dstream->to);
	if (close_parent)
		o_stream_close(dstream->ostream.parent);
}

static int
o_stream_final_trickle_flush_buffer(struct final_trickle_ostream *dstream)
{
	int ret = 1;

	if (dstream->buffer_used) {
		if ((ret = o_stream_send(dstream->ostream.parent,
					 &dstream->buffer_char, 1)) < 0)
			o_stream_copy_error_from_parent(&dstream->ostream);
		else if (ret > 0)
			dstream->buffer_used = FALSE;
		if (ret != 0)
			timeout_remove(&dstream->to);
	}
	return ret;
}

static void
o_stream_final_trickle_timeout(struct final_trickle_ostream *dstream)
{
	struct ostream *ostream = &dstream->ostream.ostream;

	i_assert(dstream->buffer_used);

	(void)o_stream_final_trickle_flush_buffer(dstream);
	o_stream_set_flush_pending(ostream, TRUE);
}

static int o_stream_final_trickle_flush(struct ostream_private *stream)
{
	struct final_trickle_ostream *dstream =
		container_of(stream, struct final_trickle_ostream, ostream);

	if (dstream->buffer_used)
		return 0;
	return o_stream_flush_parent(stream);
}

static ssize_t
o_stream_final_trickle_sendv(struct ostream_private *stream,
			     const struct const_iovec *iov,
			     unsigned int iov_count)
{
	struct final_trickle_ostream *dstream =
		container_of(stream, struct final_trickle_ostream, ostream);
	ssize_t ret;

	if ((ret = o_stream_final_trickle_flush_buffer(dstream)) <= 0)
		return ret;
	i_assert(!dstream->buffer_used);

	/* send all but the last byte */
	struct const_iovec iov_copy[iov_count];
	memcpy(iov_copy, iov, iov_count * sizeof(*iov));
	struct const_iovec *last_iov = &iov_copy[iov_count-1];

	i_assert(last_iov->iov_len > 0);
	last_iov->iov_len--;
	const unsigned char *last_iov_data = last_iov->iov_base;
	dstream->buffer_char = last_iov_data[last_iov->iov_len];
	dstream->buffer_used = TRUE;
	if (dstream->to == NULL) {
		dstream->to = timeout_add_short(0,
			o_stream_final_trickle_timeout, dstream);
	}
	if (last_iov->iov_len == 0)
		iov_count--;

	ret = 0;
	if (iov_count > 0) {
		size_t full_size = 0;
		for (unsigned int i = 0; i < iov_count; i++)
			full_size += iov_copy[i].iov_len;
		if ((ret = o_stream_sendv(stream->parent, iov_copy, iov_count)) < 0) {
			o_stream_copy_error_from_parent(stream);
			return -1;
		}
		if ((size_t)ret < full_size) {
			dstream->buffer_used = FALSE;
			timeout_remove(&dstream->to);
		}
	}
	if (dstream->buffer_used)
		ret++;

	stream->ostream.offset += ret;
	return ret;
}

static size_t
o_stream_final_trickle_get_buffer_used_size(const struct ostream_private *stream)
{
	const struct final_trickle_ostream *dstream =
		container_of(stream, const struct final_trickle_ostream, ostream);

	return (dstream->buffer_used ? 1 : 0) +
		o_stream_get_buffer_used_size(stream->parent);
}

static void
o_stream_final_trickle_switch_ioloop_to(struct ostream_private *stream,
					struct ioloop *ioloop)
{
	struct final_trickle_ostream *dstream =
		container_of(stream, struct final_trickle_ostream, ostream);

	if (dstream->to != NULL)
		dstream->to = io_loop_move_timeout_to(ioloop, &dstream->to);
	if (stream->parent != NULL)
		o_stream_switch_ioloop_to(stream->parent, ioloop);
}

struct ostream *o_stream_create_final_trickle(struct ostream *output)
{
	struct final_trickle_ostream *dstream;

	dstream = i_new(struct final_trickle_ostream, 1);
	dstream->ostream.iostream.close = o_stream_final_trickle_close;
	dstream->ostream.sendv = o_stream_final_trickle_sendv;
	dstream->ostream.flush = o_stream_final_trickle_flush;
	dstream->ostream.get_buffer_used_size = o_stream_final_trickle_get_buffer_used_size;
	dstream->ostream.switch_ioloop_to = o_stream_final_trickle_switch_ioloop_to;

	return o_stream_create(&dstream->ostream, output,
			       o_stream_get_fd(output));
}
