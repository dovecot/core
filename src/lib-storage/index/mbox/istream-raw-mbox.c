/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream-internal.h"
#include "istream-raw-mbox.h"
#include "mbox-from.h"

struct raw_mbox_istream {
	struct _istream istream;

	time_t received_time, next_received_time;
	uoff_t from_offset, body_size;
	struct istream *input;
};

static void _close(struct _iostream *stream __attr_unused__)
{
}

static void _destroy(struct _iostream *stream)
{
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;

	i_stream_seek(rstream->input, rstream->istream.istream.v_offset);
	i_stream_unref(rstream->input);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;

	i_stream_set_max_buffer_size(rstream->input, max_size);
}

static void _set_blocking(struct _iostream *stream, int timeout_msecs,
			  void (*timeout_cb)(void *), void *context)
{
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;

	i_stream_set_blocking(rstream->input, timeout_msecs,
			      timeout_cb, context);
}

static ssize_t _read(struct _istream *stream)
{
	static const char *mbox_from = "\nFrom ";
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;
	const unsigned char *buf, *p;
	const char *fromp;
	time_t received_time;
	size_t i, pos;
	ssize_t ret;

	i_stream_seek(rstream->input, stream->istream.v_offset);

	stream->pos -= stream->skip;
	stream->skip = 0;
	stream->buffer = NULL;

	do {
		ret = i_stream_read(rstream->input);
		buf = i_stream_get_data(rstream->input, &pos);
	} while (ret > 0 && pos <= 6);

	if (pos == 1 && buf[0] == '\n') {
		/* EOF */
		stream->pos = 0;
		stream->istream.eof = TRUE;
		return -1;
	}

	if (stream->istream.v_offset == rstream->from_offset) {
		/* read the full From-line */
		int skip = rstream->from_offset != 0;
		size_t line_pos;

		while ((p = memchr(buf+skip, '\n', pos-skip)) == NULL) {
			if (i_stream_read(rstream->input) < 0) {
				/* EOF - shouldn't happen */
				stream->pos = 0;
				stream->istream.eof = TRUE;
				return -1;
			}
			buf = i_stream_get_data(rstream->input, &pos);
		}
		line_pos = (size_t)(p - buf);

		if (rstream->from_offset != 0) {
			buf++;
			pos--;
		}

		/* beginning of mbox */
		if (memcmp(buf, "From ", 5) != 0)
			received_time = (time_t)-1;
		else
			received_time = mbox_from_parse_date(buf+5, pos-5);

		if (received_time == (time_t)-1) {
			/* broken From - should happen only at beginning of
			   file if this isn't a mbox.. */
			stream->pos = 0;
			stream->istream.eof = TRUE;
			return -1;
		}

		if (rstream->from_offset == 0)
			rstream->received_time = received_time;
		else
			rstream->next_received_time = received_time;

		/* we'll skip over From-line and try again */
		stream->istream.v_offset += line_pos+1;
		return _read(stream);
	}

	if (pos >= 31) {
		if (memcmp(buf, "\nFrom ", 6) == 0) {
			received_time = mbox_from_parse_date(buf+6, pos-6);
			if (received_time != (time_t)-1) {
				rstream->next_received_time = received_time;
				i_assert(stream->pos == 0);
				return -1;
			}
		}
	} else if (ret == -1) {
		/* last few bytes, can't contain From-line */
		ret = pos <= stream->pos ? -1 :
			(ssize_t) (pos - stream->pos);

		stream->buffer = buf;
		stream->pos = pos;
		stream->istream.eof = ret == -1;
		return ret;
	}

	/* See if we have From-line here - note that it works right only
	   because all characters are different in mbox_from. */
	for (i = 0, fromp = mbox_from; i < pos; i++) {
		if (buf[i] == *fromp) {
			if (*++fromp == '\0') {
				/* potential From-line - stop here */
				i++;
				break;
			}
		} else {
			fromp = mbox_from;
			if (buf[i] == *fromp)
				fromp++;
		}
	}
	pos = i - (fromp - mbox_from);

	ret = pos <= stream->pos ? -1 :
		(ssize_t) (pos - stream->pos);
	stream->buffer = buf;
	stream->pos = pos;
	return ret;
}

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
	stream->buffer = NULL;
}

struct istream *i_stream_create_raw_mbox(pool_t pool, struct istream *input)
{
	struct raw_mbox_istream *rstream;

	i_stream_ref(input);

	rstream = p_new(pool, struct raw_mbox_istream, 1);

	rstream->input = input;
	rstream->body_size = (uoff_t)-1;

	rstream->istream.iostream.close = _close;
	rstream->istream.iostream.destroy = _destroy;
	rstream->istream.iostream.set_max_buffer_size = _set_max_buffer_size;
	rstream->istream.iostream.set_blocking = _set_blocking;

	rstream->istream.read = _read;
	rstream->istream.seek = _seek;

	return _i_stream_create(&rstream->istream, pool, -1,
				input->real_stream->abs_start_offset);
}

static int istream_raw_mbox_is_valid_from(struct raw_mbox_istream *rstream)
{
	const unsigned char *data;
	size_t size;
	time_t received_time;

	/* minimal: "From x Thu Nov 29 22:33:52 2001" = 31 chars */
	if (i_stream_read_data(rstream->input, &data, &size, 30) == -1)
		return -1;

	if (size == 1 && data[0] == '\n') {
		/* EOF */
		return TRUE;
	}

	if (size < 31 || memcmp(data, "\nFrom ", 6) != 0)
		return FALSE;

	while (memchr(data+1, '\n', size-1) == NULL) {
		if (i_stream_read_data(rstream->input, &data, &size, size) < 0)
			break;
	}

	received_time = mbox_from_parse_date(data+6, size-6);
	if (received_time == (time_t)-1)
		return FALSE;

	rstream->next_received_time = received_time;
	return TRUE;
}

uoff_t istream_raw_mbox_get_size(struct istream *stream, uoff_t body_size)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;
	uoff_t old_offset;
	const unsigned char *data;
	size_t size;

	if (rstream->body_size != (uoff_t)-1)
		return rstream->body_size;

	if (body_size != (uoff_t)-1) {
		i_stream_seek(rstream->input, rstream->from_offset + body_size);
		if (istream_raw_mbox_is_valid_from(rstream) > 0) {
			rstream->body_size = body_size;
			return body_size;
		}
	}

	old_offset = stream->v_offset;

	/* have to read through the message body */
	while (i_stream_read_data(stream, &data, &size, 0) > 0)
		i_stream_skip(stream, size);

	rstream->body_size = stream->v_offset - old_offset;
	i_stream_seek(stream, old_offset);
	return rstream->body_size;
}

void istream_raw_mbox_next(struct istream *stream, uoff_t body_size)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	body_size = istream_raw_mbox_get_size(stream, body_size);
	rstream->body_size = (uoff_t)-1;

	rstream->received_time = rstream->next_received_time;
	rstream->next_received_time = (time_t)-1;

	rstream->from_offset = stream->v_offset + body_size;
	i_stream_seek(rstream->input, rstream->from_offset);
}

void istream_raw_mbox_flush(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	/* kludgy */
	rstream->input->real_stream->skip = 0;
	rstream->input->real_stream->pos = 0;

	rstream->istream.skip = 0;
	rstream->istream.pos = 0;
}
