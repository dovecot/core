/* Copyright (c) 2014-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "istream-private.h"
#include "istream-timeout.h"

struct timeout_istream {
	struct istream_private istream;

	struct timeout *to;
	struct timeval last_read_timestamp;
	time_t created;

	unsigned int timeout_msecs;
	bool update_timestamp;
};

static void i_stream_timeout_close(struct iostream_private *stream,
				   bool close_parent)
{
	struct timeout_istream *tstream = (struct timeout_istream *)stream;

	if (tstream->to != NULL)
		timeout_remove(&tstream->to);
	if (close_parent)
		i_stream_close(tstream->istream.parent);
}

static void i_stream_timeout_switch_ioloop(struct istream_private *stream)
{
	struct timeout_istream *tstream = (struct timeout_istream *)stream;

	if (tstream->to != NULL)
		tstream->to = io_loop_move_timeout(&tstream->to);
}

static void i_stream_timeout(struct timeout_istream *tstream)
{
	unsigned int over_msecs;
	int diff;

	if (tstream->update_timestamp) {
		/* we came here after a long-running code. timeouts are handled
		   before IOs, so wait for i_stream_read() to be called again
		   before assuming that we've timed out. */
		return;
	}

	timeout_remove(&tstream->to);

	diff = timeval_diff_msecs(&ioloop_timeval, &tstream->last_read_timestamp);
	if (diff < (int)tstream->timeout_msecs) {
		/* we haven't reached the read timeout yet, update it */
		if (diff < 0)
			diff = 0;
		tstream->to = timeout_add(tstream->timeout_msecs - diff,
					  i_stream_timeout, tstream);
		return;
	}
	over_msecs = diff - tstream->timeout_msecs;

	io_stream_set_error(&tstream->istream.iostream,
			    "Read timeout in %u.%03u s after %"PRIuUOFF_T" bytes%s",
			    diff/1000, diff%1000,
			    tstream->istream.istream.v_offset,
			    over_msecs < 1000 ? "" : t_strdup_printf(
			    	" (requested timeout in %u ms)", tstream->timeout_msecs));
	tstream->istream.istream.stream_errno = ETIMEDOUT;

	i_stream_set_input_pending(tstream->istream.parent, TRUE);
}

static void i_stream_timeout_set_pending(struct timeout_istream *tstream)
{
	/* make sure we get called again on the next ioloop run. this updates
	   the timeout to the timestamp where we actually would have wanted to
	   start waiting for more data (so if there is long-running code
	   outside the ioloop it's not counted) */
	tstream->update_timestamp = TRUE;
	tstream->last_read_timestamp = ioloop_timeval;
	i_stream_set_input_pending(&tstream->istream.istream, TRUE);
}

static ssize_t
i_stream_timeout_read(struct istream_private *stream)
{
	struct timeout_istream *tstream = (struct timeout_istream *)stream;
	ssize_t ret;

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);

	ret = i_stream_read_copy_from_parent(&stream->istream);
	if (ret < 0) {
		/* failed */
		if (errno == ECONNRESET || errno == EPIPE) {
			int diff = ioloop_time - tstream->created;

			io_stream_set_error(&tstream->istream.iostream,
				"%s (opened %d secs ago)",
				i_stream_get_error(stream->parent), diff);
		}
	} else if (tstream->to == NULL && tstream->timeout_msecs > 0) {
		/* first read. add the timeout here instead of in init
		   in case the stream is created long before it's actually
		   read from. */
		tstream->to = timeout_add(tstream->timeout_msecs,
					  i_stream_timeout, tstream);
		i_stream_timeout_set_pending(tstream);
	} else if (ret > 0 && tstream->to != NULL) {
		/* we read something, reset the timeout */
		timeout_reset(tstream->to);
		i_stream_timeout_set_pending(tstream);
	} else if (tstream->update_timestamp) {
		tstream->update_timestamp = FALSE;
		tstream->last_read_timestamp = ioloop_timeval;
	}
	return ret;
}

struct istream *
i_stream_create_timeout(struct istream *input, unsigned int timeout_msecs)
{
	struct timeout_istream *tstream;

	tstream = i_new(struct timeout_istream, 1);
	tstream->timeout_msecs = timeout_msecs;
	tstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	tstream->istream.stream_size_passthrough = TRUE;
	tstream->created = ioloop_time;

	tstream->istream.read = i_stream_timeout_read;
	tstream->istream.switch_ioloop = i_stream_timeout_switch_ioloop;
	tstream->istream.iostream.close = i_stream_timeout_close;

	tstream->istream.istream.readable_fd = input->readable_fd;
	tstream->istream.istream.blocking = input->blocking;
	tstream->istream.istream.seekable = input->seekable;
	return i_stream_create(&tstream->istream, input,
			       i_stream_get_fd(input));
}
