/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"
#include "istream-dot.h"

struct dot_istream {
	struct istream_private istream;

	char pending[3]; /* max. \r\n */

	/* how far in string "\r\n.\r" are we */
	unsigned int state;
	/* state didn't actually start with \r */
	unsigned int state_no_cr:1;
	/* state didn't contain \n either (only at the beginnign of stream) */
	unsigned int state_no_lf:1;
	/* we've seen the "." line, keep returning EOF */
	unsigned int dot_eof:1;

	unsigned int send_last_lf:1;
};

static int i_stream_dot_read_some(struct dot_istream *dstream)
{
	struct istream_private *stream = &dstream->istream;
	size_t size;
	ssize_t ret;

	(void)i_stream_get_data(stream->parent, &size);
	if (size == 0) {
		ret = i_stream_read(stream->parent);
		if (ret <= 0 && (ret != -2 || stream->skip == 0)) {
			if (stream->parent->stream_errno != 0) {
				stream->istream.stream_errno =
					stream->parent->stream_errno;
			} else if (ret < 0 && stream->parent->eof) {
				/* we didn't see "." line */
				stream->istream.stream_errno = EPIPE;
			}
			return ret;
		}
		(void)i_stream_get_data(stream->parent, &size);
		i_assert(size != 0);
	}

	if (!i_stream_get_buffer_space(stream, size, NULL))
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
	else if (dstream->state > 1)
		dstream->pending[i++] = '\n';
	dstream->pending[i] = '\0';

	if (dstream->state != 4)
		dstream->state = 0;
	else {
		/* \r\n.\r seen, go back to \r state */
		dstream->state = 1;
	}
	return flush_pending(dstream, destp);
}

static void i_stream_dot_eof(struct dot_istream *dstream, size_t *destp)
{
	if (dstream->send_last_lf) {
		dstream->state = 2;
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
	size_t i, dest, size;
	ssize_t ret, ret1;

	if (dstream->pending[0] != '\0') {
		if (!i_stream_get_buffer_space(stream, 1, NULL))
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
		if (ret1 != 0)
			return ret1;
		dest = stream->pos;
		if (ret == -1 && dstream->state != 0)
			(void)flush_dot_state(dstream, &dest);
		return i_stream_dot_return(stream, dest, ret);
	}
	dest = stream->pos;

	data = i_stream_get_data(stream->parent, &size);
	for (i = 0; i < size && dest < stream->buffer_size; i++) {
		switch (dstream->state) {
		case 0:
			break;
		case 1:
			/* CR seen */
			if (data[i] == '\n')
				dstream->state++;
			else {
				if (!flush_dot_state(dstream, &dest))
					goto end;
			}
			break;
		case 2:
			/* [CR]LF seen */
			if (data[i] == '.')
				dstream->state++;
			else {
				if (!flush_dot_state(dstream, &dest))
					goto end;
			}
			break;
		case 3:
			/* [CR]LF. seen */
			if (data[i] == '\r')
				dstream->state++;
			else if (data[i] == '\n') {
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
		case 4:
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
		if (dstream->state == 0) {
			if (data[i] == '\r') {
				dstream->state = 1;
				dstream->state_no_cr = FALSE;
			} else if (data[i] == '\n') {
				dstream->state = 2;
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

static const struct stat *
i_stream_dot_stat(struct istream_private *stream, bool exact)
{
	return i_stream_stat(stream->parent, exact);
}

struct istream *i_stream_create_dot(struct istream *input, bool send_last_lf)
{
	struct dot_istream *dstream;

	dstream = i_new(struct dot_istream, 1);
	dstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	dstream->istream.read = i_stream_dot_read;
	dstream->istream.stat = i_stream_dot_stat;

	dstream->istream.istream.readable_fd = FALSE;
	dstream->istream.istream.blocking = input->blocking;
	dstream->istream.istream.seekable = FALSE;
	dstream->send_last_lf = send_last_lf;
	dstream->state = 2;
	dstream->state_no_cr = TRUE;
	dstream->state_no_lf = TRUE;
	return i_stream_create(&dstream->istream, input,
			       i_stream_get_fd(input));
}
