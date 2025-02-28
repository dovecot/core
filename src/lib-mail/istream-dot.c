/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "istream-dot.h"

enum dot_state {
	DOT_STATE_SEEN_NONE	    = 0,
	DOT_STATE_SEEN_CR	    = 1,
	DOT_STATE_SEEN_CR_LF	    = 2,
	DOT_STATE_SEEN_CR_LF_DOT    = 3,
	DOT_STATE_SEEN_CR_LF_DOT_CR = 4,
};

struct dot_istream {
	struct istream_private istream;

	char pending[3]; /* max. \r\n */

	/* how far in string "\r\n.\r" are we */
	enum dot_state state;
	/* state didn't actually start with \r */
	bool state_no_cr:1;
	/* state didn't contain \n either (only at the beginning of stream) */
	bool state_no_lf:1;
	/* we've seen the "." line, keep returning EOF */
	bool dot_eof:1;

	bool send_last_lf:1;
	bool accept_bare_lf:1;
};

static int i_stream_dot_read_some(struct dot_istream *dstream)
{
	struct istream_private *stream = &dstream->istream;
	size_t size, avail;
	ssize_t ret;

	size = i_stream_get_data_size(stream->parent);
	if (size == 0) {
		ret = i_stream_read_memarea(stream->parent);
		if (ret <= 0) {
			i_assert(ret != -2); /* 0 sized buffer can't be full */
			if (stream->parent->stream_errno != 0) {
				stream->istream.stream_errno =
					stream->parent->stream_errno;
			} else if (ret < 0 && stream->parent->eof) {
				/* we didn't see "." line */
				io_stream_set_error(&stream->iostream,
					"dot-input stream ends without '.' line");
				stream->istream.stream_errno = EPIPE;
			}
			return ret;
		}
		size = i_stream_get_data_size(stream->parent);
		i_assert(size != 0);
	}

	if (!i_stream_try_alloc(stream, size, &avail))
		return -2;
	return 1;
}

static bool flush_pending(struct dot_istream *dstream, size_t *destp)
{
	struct istream_private *stream = &dstream->istream;
	size_t dest = *destp;
	unsigned int i = 0;

	for (; dstream->pending[i] != '\0' && dest < stream->buffer_size; i++)
		stream->w_buffer[dest++] = dstream->pending[i];
	memmove(dstream->pending, dstream->pending + i,
		sizeof(dstream->pending) - i);
	*destp = dest;
	return dest < stream->buffer_size;
}

static bool flush_dot_state(struct dot_istream *dstream, size_t *destp)
{
	unsigned int i = 0;

	if (!dstream->state_no_cr)
		dstream->pending[i++] = '\r';
	if (dstream->state_no_lf)
		dstream->state_no_lf = FALSE;
	else if (dstream->state > DOT_STATE_SEEN_CR)
		dstream->pending[i++] = '\n';
	dstream->pending[i] = '\0';

	if (dstream->state != DOT_STATE_SEEN_CR_LF_DOT_CR)
		dstream->state = DOT_STATE_SEEN_NONE;
	else {
		/* \r\n.\r seen, go back to \r state */
		dstream->state = DOT_STATE_SEEN_CR;
	}
	return flush_pending(dstream, destp);
}

static void i_stream_dot_eof(struct dot_istream *dstream, size_t *destp)
{
	if (dstream->send_last_lf) {
		dstream->state = DOT_STATE_SEEN_CR_LF;
		(void)flush_dot_state(dstream, destp);
	}
	dstream->dot_eof = TRUE;
}

static ssize_t
i_stream_dot_return(struct istream_private *stream, size_t dest, ssize_t ret)
{
	if (dest != stream->pos) {
		i_assert(dest > stream->pos);
		ret = dest - stream->pos;
		stream->pos = dest;
	}
	return ret;
}

static ssize_t i_stream_dot_read(struct istream_private *stream)
{
	/* @UNSAFE */
	struct dot_istream *dstream = (struct dot_istream *)stream;
	const unsigned char *data;
	size_t i, dest, size, avail;
	ssize_t ret, ret1;

	if (dstream->pending[0] != '\0') {
		if (!i_stream_try_alloc(stream, 1, &avail))
			return -2;
		dest = stream->pos;
		(void)flush_pending(dstream, &dest);
	} else {
		dest = stream->pos;
	}

	if (dstream->dot_eof) {
		stream->istream.eof = TRUE;
		return i_stream_dot_return(stream, dest, -1);
	}

	/* we have to update stream->pos before reading more data */
	ret1 = i_stream_dot_return(stream, dest, 0);
	if ((ret = i_stream_dot_read_some(dstream)) <= 0) {
		if (stream->istream.stream_errno != 0)
			return -1;
		if (ret1 != 0)
			return ret1;
		dest = stream->pos;
		if (ret == -1 && dstream->state != DOT_STATE_SEEN_NONE)
			(void)flush_dot_state(dstream, &dest);
		return i_stream_dot_return(stream, dest, ret);
	}
	dest = stream->pos;

	data = i_stream_get_data(stream->parent, &size);
	for (i = 0; i < size && dest < stream->buffer_size; i++) {
		switch (dstream->state) {
		case DOT_STATE_SEEN_NONE:
			break;
		case DOT_STATE_SEEN_CR:
			/* CR seen */
			if (data[i] == '\n')
				dstream->state = DOT_STATE_SEEN_CR_LF;
			else {
				if (!flush_dot_state(dstream, &dest))
					goto end;
			}
			break;
		case DOT_STATE_SEEN_CR_LF:
			/* [CR]LF seen */
			if (data[i] == '.')
				dstream->state = DOT_STATE_SEEN_CR_LF_DOT;
			else {
				if (!flush_dot_state(dstream, &dest))
					goto end;
			}
			break;
		case DOT_STATE_SEEN_CR_LF_DOT:
			/* [CR]LF. seen */
			if (data[i] == '\r')
				dstream->state = DOT_STATE_SEEN_CR_LF_DOT_CR;
			else if (data[i] == '\n' && dstream->accept_bare_lf) {
				/* EOF */
				i_stream_dot_eof(dstream, &dest);
				i++;
				goto end;
			} else {
				/* drop the initial dot */
				if (!flush_dot_state(dstream, &dest))
					goto end;
			}
			break;
		case DOT_STATE_SEEN_CR_LF_DOT_CR:
			/* [CR]LF.CR seen */
			if (data[i] == '\n') {
				/* EOF */
				i_stream_dot_eof(dstream, &dest);
				i++;
				goto end;
			} else {
				/* drop the initial dot */
				if (!flush_dot_state(dstream, &dest))
					goto end;
			}
		}
		if (dstream->state == DOT_STATE_SEEN_NONE) {
			if (data[i] == '\r') {
				dstream->state = DOT_STATE_SEEN_CR;
				dstream->state_no_cr = FALSE;
			} else if (data[i] == '\n' && dstream->accept_bare_lf) {
				dstream->state = DOT_STATE_SEEN_CR_LF;
				dstream->state_no_cr = TRUE;
			} else {
				stream->w_buffer[dest++] = data[i];
			}
		}
	}
end:
	i_stream_skip(stream->parent, i);

	ret = i_stream_dot_return(stream, dest, 0) + ret1;
	if (ret == 0)
		return i_stream_dot_read(stream);
	i_assert(ret > 0);
	return ret;
}

struct istream *
i_stream_create_dot(struct istream *input, enum istream_dot_flags flags)
{
	struct dot_istream *dstream;

	dstream = i_new(struct dot_istream, 1);
	dstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	dstream->istream.read = i_stream_dot_read;

	dstream->istream.istream.readable_fd = FALSE;
	dstream->istream.istream.blocking = input->blocking;
	dstream->istream.istream.seekable = FALSE;
	dstream->send_last_lf = HAS_NO_BITS(flags, ISTREAM_DOT_TRIM_TRAIL);
	dstream->accept_bare_lf = HAS_ANY_BITS(flags, ISTREAM_DOT_LOOSE_EOT);
	dstream->state = DOT_STATE_SEEN_CR_LF;
	dstream->state_no_cr = TRUE;
	dstream->state_no_lf = TRUE;
	return i_stream_create(&dstream->istream, input,
			       i_stream_get_fd(input), 0);
}
