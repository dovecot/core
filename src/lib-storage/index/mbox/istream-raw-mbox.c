/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream-internal.h"
#include "istream-raw-mbox.h"
#include "mbox-from.h"

struct raw_mbox_istream {
	struct _istream istream;

	time_t received_time, next_received_time;
	char *sender, *next_sender;

	uoff_t from_offset, hdr_offset, body_offset, mail_size;
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

static int mbox_read_from_line(struct raw_mbox_istream *rstream)
{
	const unsigned char *buf, *p;
	char *sender;
	time_t received_time;
	size_t pos, line_pos;
	int skip;

	buf = i_stream_get_data(rstream->input, &pos);
	i_assert(pos > 0);

	/* from_offset points to "\nFrom ", so unless we're at the beginning
	   of the file, skip the initial \n */
	skip = rstream->from_offset != 0;

	while ((p = memchr(buf+skip, '\n', pos-skip)) == NULL) {
		if (i_stream_read(rstream->input) < 0) {
			/* EOF - shouldn't happen */
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
	if (memcmp(buf, "From ", 5) != 0 ||
	    mbox_from_parse(buf+5, pos-5, &received_time, &sender) < 0) {
		/* broken From - should happen only at beginning of
		   file if this isn't a mbox.. */
		return -1;
	}

	if (rstream->istream.istream.v_offset == rstream->from_offset) {
		rstream->received_time = received_time;
		i_free(rstream->sender);
		rstream->sender = sender;
	} else {
		rstream->next_received_time = received_time;
		i_free(rstream->next_sender);
		rstream->next_sender = sender;
	}

	/* we'll skip over From-line */
	rstream->istream.istream.v_offset += line_pos+1;
	rstream->hdr_offset = rstream->istream.istream.v_offset;
	return 0;
}

static ssize_t _read(struct _istream *stream)
{
	static const char *mbox_from = "\nFrom ";
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;
	const unsigned char *buf;
	const char *fromp;
	char *sender, eoh_char;
	time_t received_time;
	size_t i, pos, new_pos;
	ssize_t ret;

	i_stream_seek(rstream->input, stream->istream.v_offset);

	stream->pos -= stream->skip;
	stream->skip = 0;
	stream->buffer = NULL;

	do {
		ret = i_stream_read(rstream->input);
		buf = i_stream_get_data(rstream->input, &pos);
	} while (ret > 0 && pos <= 6);

	if (pos == 0 || (pos == 1 && buf[0] == '\n')) {
		/* EOF */
		stream->pos = 0;
		stream->istream.eof = TRUE;
		rstream->mail_size = stream->istream.v_offset -
			rstream->hdr_offset;
		return -1;
	}

	if (stream->istream.v_offset == rstream->from_offset) {
		if (mbox_read_from_line(rstream) < 0) {
			stream->pos = 0;
			stream->istream.eof = TRUE;
			return -1;
		}
		return _read(stream);
	}

	i = 0;

	if (pos >= 31) {
		if (memcmp(buf, "\nFrom ", 6) == 0 &&
		    mbox_from_parse(buf+6, pos-6,
				    &received_time, &sender) == 0) {
			rstream->next_received_time = received_time;
			rstream->mail_size = stream->istream.v_offset -
				rstream->hdr_offset;

			i_free(rstream->next_sender);
			rstream->next_sender = sender;
			i_assert(stream->pos == 0);
			return -1;
		}

		/* we don't want to get stuck at invalid From-line */
		i += 6;
	} else if (ret == -1) {
		/* last few bytes, can't contain From-line */
		if (buf[pos-1] == '\n') {
			/* last LF doesn't belong to last message */
			pos--;
		}

		ret = pos <= stream->pos ? -1 :
			(ssize_t) (pos - stream->pos);

		rstream->mail_size = stream->istream.v_offset + pos -
			rstream->hdr_offset;

		stream->buffer = buf;
		stream->pos = pos;
		stream->istream.eof = ret == -1;
		return ret;
	}

	/* See if we have From-line here - note that it works right only
	   because all characters are different in mbox_from. */
	eoh_char = rstream->body_offset == (uoff_t)-1 ? '\n' : '\0';
	for (fromp = mbox_from; i < pos; i++) {
		if (buf[i] == eoh_char && i > 0 && buf[i-1] == '\n') {
			rstream->body_offset = stream->istream.v_offset + i + 1;
			eoh_char = '\0';
		}
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
	new_pos = i - (fromp - mbox_from);

	ret = new_pos <= stream->pos ? -1 :
		(ssize_t) (pos - stream->pos);
	stream->buffer = buf;
	stream->pos = new_pos;

	if (i < pos && new_pos == stream->pos) {
		/* beginning from From-line, try again */
		ret = 0;
	}

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
	rstream->body_offset = (uoff_t)-1;
	rstream->mail_size = (uoff_t)-1;
	rstream->received_time = (time_t)-1;
	rstream->next_received_time = (time_t)-1;

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
	char *sender;

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

	if (mbox_from_parse(data+6, size-6, &received_time, &sender) < 0)
		return FALSE;

	rstream->next_received_time = received_time;
	i_free(rstream->next_sender);
	rstream->next_sender = sender;
	return TRUE;
}

uoff_t istream_raw_mbox_get_start_offset(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	return rstream->from_offset;
}

uoff_t istream_raw_mbox_get_header_offset(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	if (rstream->hdr_offset == rstream->from_offset)
		(void)_read(&rstream->istream);

	return rstream->hdr_offset;
}

uoff_t istream_raw_mbox_get_body_size(struct istream *stream, uoff_t body_size)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;
	const unsigned char *data;
	size_t size;

	if (rstream->mail_size != (uoff_t)-1) {
		return rstream->mail_size -
			(rstream->body_offset - rstream->hdr_offset);
	}

	if (body_size != (uoff_t)-1) {
		i_assert(rstream->body_offset != (uoff_t)-1);
		i_stream_seek(rstream->input, rstream->body_offset + body_size);
		if (istream_raw_mbox_is_valid_from(rstream) > 0) {
			rstream->mail_size = body_size +
				(rstream->body_offset - rstream->hdr_offset);
			return body_size;
		}
	}

	/* have to read through the message body */
	while (i_stream_read_data(stream, &data, &size, 0) > 0)
		i_stream_skip(stream, size);

	i_assert(rstream->mail_size != (uoff_t)-1);
	return rstream->mail_size -
		(rstream->body_offset - rstream->hdr_offset);
}

time_t istream_raw_mbox_get_received_time(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	if (rstream->received_time == (time_t)-1)
		(void)_read(&rstream->istream);
	return rstream->received_time;
}

const char *istream_raw_mbox_get_sender(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	if (rstream->sender == NULL)
		(void)_read(&rstream->istream);
	return rstream->sender == NULL ? "" : rstream->sender;
}

void istream_raw_mbox_next(struct istream *stream, uoff_t body_size)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	body_size = istream_raw_mbox_get_body_size(stream, body_size);
	rstream->mail_size = (uoff_t)-1;

	rstream->received_time = rstream->next_received_time;
	rstream->next_received_time = (time_t)-1;

	i_free(rstream->sender);
	rstream->sender = rstream->next_sender;
	rstream->next_sender = NULL;

	rstream->from_offset = rstream->body_offset + body_size;
	rstream->hdr_offset = rstream->from_offset;
	rstream->body_offset = (uoff_t)-1;

	/* don't clear stream->eof if we don't have to */
	if (stream->v_offset != rstream->from_offset)
		i_stream_seek(stream, rstream->from_offset);
	i_stream_seek(rstream->input, rstream->from_offset);
}

void istream_raw_mbox_seek(struct istream *stream, uoff_t offset)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	if (rstream->mail_size != (uoff_t)-1 &&
	    rstream->hdr_offset + rstream->mail_size == offset) {
		istream_raw_mbox_next(stream, (uoff_t)-1);
		return;
	}

	if (offset == rstream->from_offset) {
		/* back to beginning of current message */
		offset = rstream->hdr_offset;
	} else {
		rstream->body_offset = (uoff_t)-1;
		rstream->mail_size = (uoff_t)-1;
		rstream->received_time = (time_t)-1;
		rstream->next_received_time = (time_t)-1;

		i_free(rstream->sender);
		rstream->sender = NULL;
		i_free(rstream->next_sender);
		rstream->next_sender = NULL;

                rstream->from_offset = offset;
		rstream->hdr_offset = offset;
	}

	i_stream_seek(stream, offset);
	i_stream_seek(rstream->input, offset);
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
