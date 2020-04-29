/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "ostream-private.h"

#include "ostream-wrapper.h"

static int wrapper_ostream_flush(struct ostream_private *stream);
static void
wrapper_ostream_switch_ioloop_to(struct ostream_private *stream,
				 struct ioloop *ioloop);

/*
 * Buffer
 */

/* Determine the optimum buffer size for the wrapper stream itself. */
static inline size_t
wrapper_ostream_optimal_size(struct wrapper_ostream *wostream)
{
	size_t optimal_size = wostream->ostream.max_buffer_size;

	if (wostream->output != NULL) {
		optimal_size = I_MIN(
			o_stream_get_max_buffer_size(wostream->output),
			optimal_size);
	}
	if (optimal_size == SIZE_MAX)
		optimal_size = IO_BLOCK_SIZE;

	return optimal_size;
}

/* Return the current size of the wrapper output stream buffer. */
static inline size_t wrapper_ostream_size(struct wrapper_ostream *wostream)
{
	buffer_t *buffer = wostream->buffer;

	if (buffer == NULL)
		return 0;
	return buffer->used;
}

/* Return TRUE when the wrapper stream's internal buffer is empty. */
static inline bool wrapper_ostream_is_empty(struct wrapper_ostream *wostream)
{
	return (wrapper_ostream_size(wostream) == 0);
}
/* Return TRUE when the wrapper stream's internal buffer is filled to the
   maximum. */
static inline bool wrapper_ostream_is_full(struct wrapper_ostream *wostream)
{
	return (wrapper_ostream_size(wostream) >=
		wostream->ostream.max_buffer_size);
}
/* Return TRUE when the wrapper stream's internal buffer is filled at or beyond
   the optimum. */
static inline bool wrapper_ostream_is_filled(struct wrapper_ostream *wostream)
{
	return (wrapper_ostream_size(wostream) >=
		wrapper_ostream_optimal_size(wostream));
}

/*
 * Underlying output
 */

/* Handle error in the underlying output stream (the parent). */
static void
wrapper_ostream_handle_parent_error(struct wrapper_ostream *wostream)
{
	i_assert(wostream->output != NULL);

	wostream->ostream.ostream.stream_errno =
		wostream->output->stream_errno;
	wostream->ostream.ostream.overflow =
		wostream->output->overflow;
	if (wostream->output->closed)
		o_stream_close(&wostream->ostream.ostream);

	if (wostream->output_error != NULL)
		wostream->output_error(wostream);
}

static void wrapper_ostream_closed(struct wrapper_ostream *wostream)
{
	wostream->ostream.ostream.closed = TRUE;
}

/* Drop the underlying output. */
static void wrapper_ostream_output_close(struct wrapper_ostream *wostream)
{
	o_stream_unref(&wostream->output);
	wostream->output_finished = TRUE;
	wostream->output_closed = TRUE;
	wostream->output_closed_api = TRUE;
}

/* Method calls */

/* Called when the implementation should start making the parent output stream
   available, e.g. connect to the server (see output_start() method).
 */
static void wrapper_ostream_output_start(struct wrapper_ostream *wostream)
{
	if (wostream->output_started)
		return;
	wostream->output_started = TRUE;
	if (wostream->output_start != NULL)
		wostream->output_start(wostream);
}

/* Returns TRUE when the output is ready for data (see output_ready() method).
 */
static bool wrapper_ostream_output_ready(struct wrapper_ostream *wostream)
{
	i_assert(wostream->output_ready != NULL);
	return wostream->output_ready(wostream);
}

/* Finish the underlying output (see output_finish() method).*/
static int wrapper_ostream_output_finish(struct wrapper_ostream *wostream)
{
	i_assert(wostream->output_finish != NULL);
	return wostream->output_finish(wostream);
}

/* Called when the wrapper ostream does not need write to parent output stream.
   (see output_halt() method).
 */
static void wrapper_ostream_output_halt(struct wrapper_ostream *wostream)
{
	if (wostream->output_closed)
		return;
	if (wostream->output_halt != NULL)
		wostream->output_halt(wostream);
}

/* Called when the wrapper ostream has data available for the parent output and
   wants wrapper_ostream_continue() to be called when the parent stream is
   writeable (see output_resume() method). */
static void wrapper_ostream_output_resume(struct wrapper_ostream *wostream)
{
	if (wostream->output_closed)
		return;
	if (wostream->output_resume != NULL)
		wostream->output_resume(wostream);
}

/* Update any timeouts for the underlying (parent) output (see
  output_update_timeouts() method). */
static void
wrapper_ostream_output_update_timeouts(struct wrapper_ostream *wostream)
{
	struct ostream_private *stream = &wostream->ostream;
	bool sender_blocking;

	if (wostream->output_closed)
		return;
	if (wostream->output_update_timeouts == NULL)
		return;

	sender_blocking = (!stream->finished &&
			   (wrapper_ostream_is_empty(wostream) ||
			    (stream->corked &&
			     !wrapper_ostream_is_filled(wostream))));
	wostream->output_update_timeouts(wostream, sender_blocking);
}

/*
 * Wrapper
 */

/* Halt/resume the underlying output based on the state of the wrapper stream.
 */
static void
wrapper_ostream_output_manage(struct wrapper_ostream *wostream, bool sending)
{
	struct ostream_private *stream = &wostream->ostream;
	bool must_flush, no_data;

	if (wostream->output_closed)
		return;

	must_flush = (sending || stream->finished || wostream->flush_pending);
	no_data = (wrapper_ostream_is_empty(wostream) ||
		   (stream->corked && !wrapper_ostream_is_filled(wostream)));

	if (!must_flush && (no_data || stream->ostream.closed))
		wrapper_ostream_output_halt(wostream);
	else {
		wrapper_ostream_output_resume(wostream);
		if (wostream->output != NULL && must_flush)
			o_stream_set_flush_pending(wostream->output, TRUE);
	}
}

/* Handle any pending error by making it available to the application through
   the output stream API. */
static int
wrapper_ostream_handle_pending_error(struct wrapper_ostream *wostream)
{
	struct ostream_private *stream = &wostream->ostream;

	if (wostream->pending_errno != 0) {
		if (wostream->pending_error != NULL) {
			io_stream_set_error(&stream->iostream,
					    "%s", wostream->pending_error);
		}
		stream->ostream.stream_errno = wostream->pending_errno;
		wostream->pending_errno = 0;
		wostream->returned_error = TRUE;
		wrapper_ostream_closed(wostream);
		i_free_and_null(wostream->pending_error);
		return -1;
	}
	return 0;
}

/* Called when the wrapper stream is first finished using o_stream_finish(). */
static int wrapper_ostream_finish(struct wrapper_ostream *wostream)
{
	int ret;

	if (wostream->output_closed) {
		if (wrapper_ostream_handle_pending_error(wostream) < 0)
			return -1;
		return 1;
	}

	if (!wrapper_ostream_output_ready(wostream)) {
		return 0;
	}

	wostream->output_finished = TRUE;
	if (wostream->output != NULL) {
		if (o_stream_uncork_flush(wostream->output) < 0) {
			wrapper_ostream_handle_parent_error(wostream);
			o_stream_unref(&wostream->output);
			return -1;
		}
	}

	/* Finished sending payload; now also finish the underlying output. */
	ret = wrapper_ostream_output_finish(wostream);
	if (ret <= 0)
		return ret;

	if (wrapper_ostream_handle_pending_error(wostream) < 0)
		return -1;
	wrapper_ostream_output_close(wostream);
	return 1;
}

/* Wait in ioloop until underlying (parent) output can be flushed. This is
   called only when the wrapper stream is blocking. */
static int
wrapper_ostream_flush_wait(struct wrapper_ostream *wostream)
{
	struct ostream_private *stream = &wostream->ostream;
	struct ioloop *ioloop, *prev_ioloop;
	bool was_corked = FALSE;

	wrapper_ostream_output_manage(wostream, !wostream->flushing);

	/* Cannot be already waiting */
	i_assert(!wostream->flush_waiting);
	i_assert(wostream->flush_ioloop == NULL);

	i_assert(wostream->wait_begin != NULL);
	i_assert(wostream->wait_end != NULL);

	if (wostream->output != NULL && o_stream_is_corked(wostream->output)) {
		/* Make sure parent is uncorked here to make sure output IO is
		   active. */
		if (o_stream_uncork_flush(wostream->output) < 0) {
			wrapper_ostream_handle_parent_error(wostream);
			return -1;
		}
		was_corked = TRUE;
	}

	wostream->flush_ioloop = ioloop = io_loop_create();
	prev_ioloop = wostream->wait_begin(wostream, ioloop);
	o_stream_switch_ioloop_to(&wostream->ostream.ostream, ioloop);

	/* Either we're waiting for network I/O or we're getting out of a
	   callback using timeout_add_short(0) */
	i_assert(io_loop_have_ios(ioloop) ||
		 io_loop_have_immediate_timeouts(ioloop));

	wostream->flush_waiting = TRUE;
	do {
		e_debug(wostream->event, "Waiting for output flush");
		io_loop_run(ioloop);
	} while (wostream->flush_waiting);

	e_debug(wostream->event, "Can now flush output");

	o_stream_switch_ioloop_to(&wostream->ostream.ostream, prev_ioloop);
	wostream->wait_end(wostream, prev_ioloop);
	io_loop_destroy(&ioloop);
	wostream->flush_ioloop = NULL;

	if (stream->ostream.blocking)
		wrapper_ostream_output_halt(wostream);

	if (was_corked && wostream->output != NULL)
		o_stream_cork(wostream->output);

	if (wrapper_ostream_handle_pending_error(wostream) < 0) {
		/* Stream already hit an error */
		return -1;
	}
	return 0;
}

/* Try to flush the underlying (parent) output. */
static int wrapper_ostream_flush_parent(struct wrapper_ostream *wostream)
{
	struct ostream *parent;

	if (wostream->output_closed) {
		/* Output already dropped; nothing to flush */
		return 1;
	}
	if (!wrapper_ostream_output_ready(wostream)) {
		/* There is no parent ostream yet */
		return 1;
	}

	parent = wostream->output;
	if (parent == NULL) {
		/* There is no parent ostream anymore */
		i_assert(wostream->buffer == NULL ||
			 wostream->buffer->used == 0);
		return 1;
	}
	if (o_stream_get_buffer_used_size(parent) >= IO_BLOCK_SIZE) {
		/* We already have quite a lot of data in parent stream.
		   unless we can flush it, don't add any more to it or we
		   could keep wasting memory by just increasing the buffer
		   size all the time. */
		if (o_stream_flush(parent) < 0) {
			wrapper_ostream_handle_parent_error(wostream);
			return -1;
		}
		if (o_stream_get_buffer_used_size(parent) >= IO_BLOCK_SIZE)
			return 0;
	}

	return 1;
}

/* Try to write data to underlying (parent) output. */
static ssize_t
wrapper_ostream_writev(struct wrapper_ostream *wostream,
		       const struct const_iovec *iov, unsigned int iov_count)
{
	struct ostream *parent = wostream->output;
	ssize_t sent;

	i_assert(!wostream->output_closed);
	i_assert(!wostream->output_finished);

	if (!wrapper_ostream_output_ready(wostream))
		return 0;

	/* Send more data to parent ostream */
	i_assert(parent != NULL);
	o_stream_set_max_buffer_size(parent, IO_BLOCK_SIZE);
	sent = o_stream_sendv(parent, iov, iov_count);
	o_stream_set_max_buffer_size(parent, (size_t)-1);
	if (sent < 0) {
		wrapper_ostream_handle_parent_error(wostream);
		return -1;
	}

	return sent;
}

/* Try to write data to underlying (parent) output and implement blocking
   behavior by running an ioloop. */
static ssize_t
wrapper_ostream_writev_full(struct wrapper_ostream *wostream,
			    const struct const_iovec *iov,
			    unsigned int iov_count)
{
	struct ostream_private *stream = &wostream->ostream;
	unsigned int i;
	ssize_t sent, sent_total;

	if (!stream->ostream.blocking) {
		/* Not blocking; send what we can */
		return wrapper_ostream_writev(wostream, iov, iov_count);
	}

	/* Blocking; loop and wait until all is sent */

	sent_total = 0;
	for (;;) {
		struct const_iovec niov;
		size_t iov_pos;

		i_assert(iov_count > 0);

		/* Send iovec with complete entries */
		sent = wrapper_ostream_writev(wostream, iov, iov_count);
		if (sent < 0)
			return -1;
		if (sent == 0) {
			if (wrapper_ostream_flush_wait(wostream) < 0)
				return -1;
			i_assert(!wostream->output_closed);
			continue;
		}

		/* Determine what was sent */
		sent_total += sent;
		iov_pos = (size_t)sent;
		for (i = 0; i < iov_count && iov_pos >= iov[i].iov_len; i++)
			iov_pos -= iov[i].iov_len;
		if (i >= iov_count) {
			/* All sent */
			i_assert(iov_pos == 0);
			return sent_total;
		}

		iov = &iov[i];
		iov_count -= i;
		if (iov_pos == 0) {
			/* Nicely sent until an iovec boundary */
			continue;
		}

		/* Send partial iovec entry */
		i_zero(&niov);
		niov = iov[0];
		i_assert(iov_pos < niov.iov_len);
		niov.iov_base = CONST_PTR_OFFSET(niov.iov_base, iov_pos);
		niov.iov_len -= iov_pos;

		while (niov.iov_len > 0) {
			sent = wrapper_ostream_writev(wostream, &niov, 1);
			if (sent < 0)
				return sent;
			if (sent == 0) {
				if (wrapper_ostream_flush_wait(wostream) < 0)
					return -1;
				i_assert(!wostream->output_closed);
				continue;
			}
			i_assert((size_t)sent <= niov.iov_len);
			niov.iov_base = CONST_PTR_OFFSET(niov.iov_base, sent);
			niov.iov_len -= sent;
			sent_total += sent;
		}

		if (iov_count == 1) {
			i_assert(sent_total != 0);
			return sent_total;
		}

		/* Now sent until an iovec boundary */
		iov = &iov[1];
		iov_count--;
	}

	i_unreached();
}

/* Try to flush wrapper stream's buffer content. */
static int wrapper_ostream_flush_buffer(struct wrapper_ostream *wostream)
{
	struct ostream_private *stream = &wostream->ostream;
	buffer_t *buffer = wostream->buffer;
	struct const_iovec iov;
	ssize_t sent;

	if (wostream->output_closed) {
		/* Ostream already finished */
		i_assert(wostream->ostream.finished);
		return 1;
	}

	if (buffer == NULL || buffer->used == 0) {
		/* Buffer already empty */
		return 1;
	}

	do {
		/* Try to flush whole buffer */
		iov.iov_base = buffer->data;
		iov.iov_len = buffer->used;
		sent = wrapper_ostream_writev_full(wostream, &iov, 1);
		if (sent < 0)
			return -1;

		/* Remove sent data from buffer */
		buffer_delete(buffer, 0, sent);

		/* More aggressively flush the buffer when this stream is
		   finished
		 */
	} while (wostream->ostream.finished && sent > 0 && buffer->used > 0);

	if (buffer->used == 0 ||
	    (stream->corked && !wrapper_ostream_is_filled(wostream)))
		wrapper_ostream_output_halt(wostream);

	return (buffer->used == 0 ? 1 : 0);
}

static int wrapper_ostream_flush_real(struct wrapper_ostream *wostream)
{
	struct ostream_private *stream = &wostream->ostream;
	int ret;

	if (wrapper_ostream_handle_pending_error(wostream) < 0) {
		/* Stream already hit an error */
		return -1;
	}
	wrapper_ostream_output_start(wostream);

	if ((ret = wrapper_ostream_flush_parent(wostream)) <= 0) {
		/* Try to flush parent stream first to make room for more
		   data */
		return ret;
	}
	if ((ret = wrapper_ostream_flush_buffer(wostream)) <= 0) {
		/* Try sending data we already buffered */
		return ret;
	}

	if (wostream->output_closed || wostream->output_finished) {
		/* Already finished the ostream */
		i_assert(stream->finished);
		return 1;
	}

	if (!wrapper_ostream_output_ready(wostream)) {
		return ((wostream->buffer == NULL ||
			 wostream->buffer->used == 0) ? 1 : 0);
	}

	if (wostream->output == NULL) {
		i_assert(wrapper_ostream_is_empty(wostream));
		ret = 1;
	} else {
		ret = o_stream_flush(wostream->output);
		if (ret < 0)
			wrapper_ostream_handle_parent_error(wostream);
	}

	return ret;
}

static bool
wrapper_ostream_send_prepare(struct wrapper_ostream *wostream, size_t size)
{
	struct ostream_private *stream = &wostream->ostream;

	if (wostream->output_closed || wostream->output_started)
		return TRUE;

	if (stream->corked && !stream->finished) {
		if (wostream->buffer == NULL)
			return FALSE;
		if ((wostream->buffer->used + size) < stream->max_buffer_size)
			return FALSE;
	}
	wrapper_ostream_output_start(wostream);
	return TRUE;
}

/* Add data to the wrapper stream's internal buffer. */
static size_t
wrapper_ostream_add(struct wrapper_ostream *wostream,
		    const struct const_iovec *iov,
		    unsigned int iov_count, unsigned int *iov_idx,
		    size_t *iov_idx_pos)
{
	buffer_t *buffer = wostream->buffer;
	unsigned int i;
	size_t added = 0;

	/* Create buffer */
	if (buffer == NULL) {
		wostream->buffer = buffer =
			buffer_create_dynamic(default_pool, IO_BLOCK_SIZE);
	}

	for (i = *iov_idx; i < iov_count; i++) {
		size_t iov_len, iov_add, space;
		const unsigned char *iov_data;

		iov_len = iov[i].iov_len;
		iov_data = iov[i].iov_base;
		space = wostream->ostream.max_buffer_size - buffer->used;

		i_assert(*iov_idx_pos < iov_len);
		if (*iov_idx_pos > 0) {
			iov_len -= *iov_idx_pos;
			iov_data += *iov_idx_pos;
		}
		iov_add = I_MIN(space, iov_len);
		buffer_append(buffer, iov_data, iov_add);
		added += iov_add;
		if (iov_add < iov_len) {
			/* Buffer is full */
			*iov_idx_pos += iov_add;
			break;
		}
		*iov_idx_pos = 0;
	}

	*iov_idx = i;
	return added;
}

static ssize_t
wrapper_ostream_sendv_real(struct wrapper_ostream *wostream,
			   const struct const_iovec *iov,
			   unsigned int iov_count)
{
	struct ostream_private *stream = &wostream->ostream;
	ssize_t written;
	size_t size, iov_pos, sent;
	unsigned int i;
	int ret;

	if (wrapper_ostream_handle_pending_error(wostream) < 0) {
		/* Stream already hit an error */
		return -1;
	}

	i_assert(!wostream->output_closed);
	i_assert(!wostream->output_finished);

	/* Determine total size of data to send */
	size = 0;
	for (i = 0; i < iov_count; i++)
		size += iov[i].iov_len;

	/* Flush buffer if required */
	if (!wrapper_ostream_is_empty(wostream) &&
	    (!stream->corked || wrapper_ostream_is_filled(wostream)) &&
	    wrapper_ostream_send_prepare(wostream, size) &&
	    (ret = wrapper_ostream_flush_buffer(wostream)) < 0)
		return -1;

	if (!stream->corked && wrapper_ostream_is_full(wostream)) {
		/* No space in buffer for more data */
		i_assert(!stream->ostream.blocking);
		return 0;
	}

	/* Send data to connection directly if possible */
	i = 0;
	sent = iov_pos = 0;
	if (wrapper_ostream_is_empty(wostream) &&
	    (!stream->corked ||
	     size >= wrapper_ostream_optimal_size(wostream)) &&
	    wrapper_ostream_send_prepare(wostream, size)) {
		written = wrapper_ostream_writev_full(wostream, iov, iov_count);
		if (written < 0)
			return -1;
		sent += written;
		if (sent == size) {
			/* All sent */
			return (ssize_t)sent;
		}

		i_assert(!stream->ostream.blocking);

		/* Determine send position */
		iov_pos = sent;
		for (; i < iov_count && iov_pos >= iov[i].iov_len; i++)
			iov_pos -= iov[i].iov_len;
		i_assert(i < iov_count);
	}

	/* Fill buffer with remainder that was not sent directly */
	for (;;) {
		sent += wrapper_ostream_add(wostream, iov, iov_count,
					    &i, &iov_pos);
		i_assert(sent <= size);

		if (!stream->corked || !wrapper_ostream_is_filled(wostream))
			break;

		/* Flush corked full buffer */
		wrapper_ostream_output_start(wostream);
		if ((ret = wrapper_ostream_flush_buffer(wostream)) < 0)
			return -1;
		if (ret == 0)
			break;
	}

	i_assert(!stream->ostream.blocking || sent == size);
	return sent;
}

/* Run the flush callback for the wrapper stream. */
static int wrapper_ostream_callback(struct wrapper_ostream *wostream)
{
	int ret;

	if (wostream->ostream.callback != NULL) {
		if (wostream->callback_pre != NULL)
			wostream->callback_pre(wostream);
		ret = wostream->ostream.callback(wostream->ostream.context);
		if (wostream->callback_post != NULL)
			wostream->callback_post(wostream);
	} else {
		ret = wrapper_ostream_flush(&wostream->ostream);
	}
	return ret;
}

/* Handle an event by running wrapper_ostream_continue(). This called from
   ioloop on a zero timeout. */
static void wrapper_ostream_handle_event(struct wrapper_ostream *wostream)
{
	timeout_remove(&wostream->to_event);
	(void)wrapper_ostream_continue(wostream);
}

/*
 * iostream methods
 */

static void
wrapper_ostream_close(struct iostream_private *stream,
		      bool close_parent ATTR_UNUSED)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;

	timeout_remove(&wostream->to_event);
	wrapper_ostream_output_close(wostream);
	if (wostream->close != NULL)
		wostream->close(wostream);
}

static void wrapper_ostream_destroy(struct iostream_private *stream)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;

	timeout_remove(&wostream->to_event);
	i_free(wostream->pending_error);

	if (wostream->destroy != NULL)
		wostream->destroy(wostream);
	buffer_free(&wostream->buffer);
	o_stream_unref(&wostream->output);
	event_unref(&wostream->event);
}

/*
 * ostream methods
 */

static void wrapper_ostream_cork(struct ostream_private *stream, bool set)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;
	int ret;

	if (stream->ostream.closed || wostream->pending_errno != 0)
		return;

	if (wostream->output_closed) {
		i_assert(wostream->ostream.finished);
		return;
	}

	if (set) {
		if (wostream->output != NULL)
			o_stream_cork(wostream->output);
	} else {
		/* Buffer flushing might close the stream */
		ret = wrapper_ostream_flush_buffer(wostream);
		stream->last_errors_not_checked = TRUE;

		if (wostream->output != NULL) {
			if (o_stream_uncork_flush(wostream->output) < 0) {
				wrapper_ostream_handle_parent_error(wostream);
				ret = -1;
			}
		}
		if ((ret == 0 || wostream->flush_pending) &&
		    !stream->ostream.closed)
			wrapper_ostream_output_resume(wostream);
	}
	stream->corked = set;

	wrapper_ostream_output_manage(wostream, FALSE);
}

static ssize_t
wrapper_ostream_sendv(struct ostream_private *stream,
		      const struct const_iovec *iov, unsigned int iov_count)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;
	bool must_uncork = FALSE;
	ssize_t sret;

	if (wrapper_ostream_handle_pending_error(wostream) < 0) {
		/* Stream already hit an error */
		return -1;
	}

	/* Cork parent ostream if necessary */
	if (!wostream->output_closed && wostream->output != NULL &&
	    !o_stream_is_corked(wostream->output)) {
		o_stream_cork(wostream->output);
		must_uncork = TRUE;
	}

	sret = wrapper_ostream_sendv_real(wostream, iov, iov_count);
	if (sret > 0)
		stream->ostream.offset += (ssize_t)sret;

	/* Uncork the parent ostream */
	if (must_uncork && !wostream->output_closed &&
	    wostream->output != NULL) {
		if (o_stream_uncork_flush(wostream->output) < 0 &&
		    sret >= 0) {
			wrapper_ostream_handle_parent_error(wostream);
			sret = -1;
		}
	}

	if (sret >= 0) {
		wrapper_ostream_output_update_timeouts(wostream);
		if (!stream->ostream.blocking)
			wrapper_ostream_output_manage(wostream, FALSE);
	}

	return sret;
}

static int wrapper_ostream_flush(struct ostream_private *stream)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;
	struct ostream *ostream = &stream->ostream;
	bool must_uncork = FALSE;
	int ret;

	if (wrapper_ostream_handle_pending_error(wostream) < 0) {
		/* Stream already hit an error */
		return -1;
	}

	if (wostream->output_closed) {
		if (!stream->finished || !wrapper_ostream_is_empty(wostream)) {
			stream->ostream.stream_errno = EPIPE;
			return -1;
		}
		/* Already finished the ostream */
		return 1;
	}

	if (wostream->flushing) {
		/* Prevent recursion while finishing output */
		return 1;
	}
	wostream->flushing = TRUE;
	o_stream_ref(ostream);

	/* Cork parent ostream if necessary */
	if (wostream->output != NULL && !o_stream_is_corked(wostream->output)) {
		o_stream_cork(wostream->output);
		must_uncork = TRUE;
	}

	/* If blocking: loop until all is flushed; otherwise try once */
	do {
		/* Try to flush */
		if ((ret = wrapper_ostream_flush_real(wostream)) < 0) {
			ret = -1;
			break;
		}

		if (ret == 0 && stream->ostream.blocking) {
			/* Block until we can write more */
			if (wrapper_ostream_flush_wait(wostream) < 0) {
				ret = -1;
				break;
			}
		}

		if (stream->ostream.closed) {
			/* Ostream was closed in the mean time */
			ret = -1;
			break;
		}

		if (wostream->output_closed) {
			/* Already finished the ostream */
			i_assert(stream->finished);
			ret = 1;
			break;
		}
	} while (ret == 0 && stream->ostream.blocking);

	if (ret > 0 && stream->finished) {
		/* This was an o_stream_finish() call or subsequent flush */
		i_assert(wrapper_ostream_is_empty(wostream));
		while ((ret = wrapper_ostream_finish(wostream)) == 0) {
			if (!stream->ostream.blocking) {
				/* Not yet finished completely */
				break;
			}
			/* Block until we can write more */
			if (wrapper_ostream_flush_wait(wostream) < 0) {
				ret = -1;
				break;
			}
		}
	}
	wrapper_ostream_output_update_timeouts(wostream);
	wostream->flushing = FALSE;

	if (ret >= 0 && !ostream->blocking)
		wrapper_ostream_output_manage(wostream, FALSE);

	if (wostream->output_closed) {
		i_assert(ret < 0 || ostream->stream_errno == 0 ||
			 ostream->closed);
		o_stream_unref(&ostream);
		return (ret >= 0 ? 1 : -1);
	}

	if (!must_uncork || wostream->output == NULL) {
		/* Nothing */
	} else if (ret >= 0) {
		/* Uncork the parent ostream */
		if (o_stream_uncork_flush(wostream->output) < 0) {
			wrapper_ostream_handle_parent_error(wostream);
			ret = -1;
		}
	} else {
		o_stream_uncork(wostream->output);
	}
	o_stream_unref(&ostream);

	return ret;
}

static void
wrapper_ostream_set_flush_callback(struct ostream_private *stream,
				   stream_flush_callback_t *callback,
				   void *context)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;

	stream->callback = callback;
	stream->context = context;

	if (!stream->ostream.blocking && stream->callback == NULL) {
		/* Application is currently not interested in flush events and
		   that includes request events like errors. */
		timeout_remove(&wostream->to_event);
	} else if (wostream->pending_error != NULL &&
		   wostream->to_event == NULL) {
		/* Schedule flush callback to notify application of events */
		wostream->to_event = timeout_add_short(
			0, wrapper_ostream_handle_event, wostream);
	}
}

static void
wrapper_ostream_flush_pending(struct ostream_private *stream, bool set)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;

	wostream->flush_pending = set;
	if (!set)
		return;
	if (wostream->output_closed) {
		i_assert(wostream->ostream.ostream.closed);
		return;
	}
	if (wostream->to_event == NULL) {
		wostream->to_event = timeout_add_short(
			0, wrapper_ostream_handle_event, wostream);
	}
}

static size_t
wrapper_ostream_get_buffer_used_size(const struct ostream_private *stream)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;
	size_t size = 0;

	if (wostream->buffer != NULL)
		size += wostream->buffer->used;
	if (wostream->output != NULL)
		size += o_stream_get_buffer_used_size(wostream->output);
	return size;
}

static size_t
wrapper_ostream_get_buffer_avail_size(const struct ostream_private *stream)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;
	size_t size = 0;

	if (wostream->ostream.max_buffer_size == (size_t)-1)
		return (size_t)-1;

	if (wostream->buffer == NULL)
		size = wostream->ostream.max_buffer_size;
	else if (wostream->buffer->used < wostream->ostream.max_buffer_size) {
		size = (wostream->ostream.max_buffer_size -
			wostream->buffer->used);
	}

	if (wostream->output != NULL)
		size += o_stream_get_buffer_avail_size(wostream->output);

	return size;
}

static void
wrapper_ostream_switch_ioloop_to(struct ostream_private *stream,
				 struct ioloop *ioloop)
{
	struct wrapper_ostream *wostream = (struct wrapper_ostream *)stream;

	if (wostream->flush_ioloop != ioloop &&
	    wostream->switch_ioloop_to != NULL)
		wostream->switch_ioloop_to(wostream, ioloop);

	if (wostream->to_event != NULL) {
		wostream->to_event =
			io_loop_move_timeout_to(ioloop, &wostream->to_event);
	}
}

/*
 * API
 */

struct ostream *
wrapper_ostream_create(struct wrapper_ostream *wostream,
		       size_t max_buffer_size, bool blocking,
		       struct event *event)
{
	wostream->ostream.iostream.close = wrapper_ostream_close;
	wostream->ostream.iostream.destroy = wrapper_ostream_destroy;

	wostream->ostream.ostream.blocking = blocking;
	wostream->ostream.max_buffer_size = max_buffer_size;
	wostream->ostream.cork = wrapper_ostream_cork;
	wostream->ostream.sendv = wrapper_ostream_sendv;
	wostream->ostream.flush = wrapper_ostream_flush;
	wostream->ostream.set_flush_callback =
		wrapper_ostream_set_flush_callback;
	wostream->ostream.flush_pending = wrapper_ostream_flush_pending;
	wostream->ostream.get_buffer_used_size =
		wrapper_ostream_get_buffer_used_size;
	wostream->ostream.get_buffer_avail_size =
		wrapper_ostream_get_buffer_avail_size;
	wostream->ostream.switch_ioloop_to =
		wrapper_ostream_switch_ioloop_to;

	wostream->event = event_create(event);

	return o_stream_create(&wostream->ostream, NULL, -1);
}

int wrapper_ostream_continue(struct wrapper_ostream *wostream)
{
	struct ostream_private *stream = &wostream->ostream;
	struct ostream *ostream = &stream->ostream;
	struct ioloop *ioloop = NULL;
	bool use_cork = !stream->corked;
	int ret = 1;

	if (wostream->flush_waiting) {
		/* Inside wrapper_ostream_flush_wait() */
		ioloop = wostream->flush_ioloop;
	}
	if (stream->ostream.closed ||
	    (stream->finished && wrapper_ostream_is_empty(wostream) &&
	     wostream->output != NULL &&
	     o_stream_get_buffer_used_size(wostream->output) == 0)) {
		/* Already finished */
		ret = wrapper_ostream_finish(wostream);
		if (ret == 0)
			return 0;
	}
	if (wostream->flush_waiting) {
		i_assert(ioloop != NULL);
		io_loop_stop(ioloop);
		wostream->flush_waiting = FALSE;
		return ret;
	}

	/* Set flush_pending = FALSE first before calling the flush callback,
	   and change it to TRUE only if callback returns 0. That way the
	   callback can call o_stream_set_flush_pending() again and we don't
	   forget it even if flush callback returns 1. */
	wostream->flush_pending = FALSE;

	o_stream_ref(ostream);
	wostream->continuing = TRUE;
	for (;;) {
		if (use_cork)
			o_stream_cork(ostream);
		ret = wrapper_ostream_callback(wostream);
		if (use_cork && !wostream->output_closed) {
			int fret = o_stream_uncork_flush(ostream);
			if (ret == 0 && fret > 0)
				continue;
			if (fret < 0 && ret >= 0) {
				i_assert(ostream->stream_errno != 0);
				(void)wrapper_ostream_callback(wostream);
				ret = -1;
			}
		}
		break;
	}
	wostream->continuing = FALSE;
	if (wostream->output_closed)
		o_stream_close(ostream);

	if (ret == 0)
		wostream->flush_pending = TRUE;

	if (!stream->ostream.blocking)
		wrapper_ostream_output_manage(wostream, FALSE);

	if (ret < 0 || ostream->stream_errno != 0 ||
	    wostream->pending_errno != 0)
		ret = -1;
	else if (wostream->output_closed)
		ret = 1;
	else if (!wrapper_ostream_is_empty(wostream) &&
		 (!stream->corked || wrapper_ostream_is_filled(wostream)))
		ret = 0;
	else if (wostream->flush_pending)
		ret = 0;

	o_stream_unref(&ostream);

	return ret;
}

void wrapper_ostream_trigger_flush(struct wrapper_ostream *wostream)
{
	struct ostream *ostream = &wostream->ostream.ostream;

	if (ostream->closed)
		return;
	if (wostream->to_event != NULL)
		return;
	if (!wostream->flush_waiting && wostream->ostream.callback == NULL)
		return;

	wostream->to_event = timeout_add_short(
		0, wrapper_ostream_handle_event, wostream);
}

bool wrapper_ostream_get_buffered_size(struct wrapper_ostream *wostream,
				       uoff_t *size_r)
{
	buffer_t *buffer = wostream->buffer;

	if (!wostream->ostream.finished)
		return FALSE;

	*size_r = (buffer == NULL ? 0 : (uoff_t)buffer->used);
	i_assert(*size_r == wostream->ostream.ostream.offset);
	return TRUE;
}

void wrapper_ostream_output_available(struct wrapper_ostream *wostream,
				      struct ostream *output)
{
	i_assert(!wostream->output_closed);
	i_assert(!wostream->output_finished);
	i_assert(wostream->output == NULL);
	wostream->output = output;
	if (output != NULL) {
		if (wostream->ostream.corked)
			o_stream_cork(wostream->output);
		o_stream_ref(output);
	}
}

void wrapper_ostream_output_destroyed(struct wrapper_ostream *wostream)
{
	struct ostream *ostream = &wostream->ostream.ostream;

	wrapper_ostream_trigger_flush(wostream);
	o_stream_set_no_error_handling(ostream, TRUE);

	o_stream_unref(&wostream->output);
	wostream->output_closed = TRUE;
	wostream->output_finished = TRUE;
}

void wrapper_ostream_set_error(struct wrapper_ostream *wostream,
			       int stream_errno, const char *stream_error)
{
	struct ostream *ostream = &wostream->ostream.ostream;

	if (ostream->closed || wostream->pending_errno != 0 ||
	    wostream->returned_error)
		return;

	i_assert(wostream->pending_error == NULL);
	wostream->pending_errno = stream_errno;
	wostream->pending_error = i_strdup(stream_error);

	wrapper_ostream_trigger_flush(wostream);
}

void wrapper_ostream_notify_error(struct wrapper_ostream *wostream)
{
	struct ostream *ostream = &wostream->ostream.ostream;

	if (ostream->closed || ostream->blocking ||
	    wostream->output_closed_api || wostream->returned_error ||
	    wostream->continuing)
		return;
	if (wostream->pending_errno == 0)
		return;
	wostream->returned_error = TRUE;
	(void)wrapper_ostream_callback(wostream);
}
