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
	uoff_t input_peak_offset;

	unsigned int corrupted:1;
	unsigned int eom:1;
	unsigned int eof:1;
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
	i_stream_skip(rstream->input, line_pos+1);
	rstream->hdr_offset = rstream->istream.istream.v_offset;
	return 0;
}

static void handle_end_of_mail(struct raw_mbox_istream *rstream, size_t pos)
{
	rstream->mail_size = rstream->istream.istream.v_offset + pos -
		rstream->hdr_offset;

	if (rstream->body_offset != (uoff_t)-1 &&
	    rstream->hdr_offset + rstream->mail_size < rstream->body_offset) {
		/* "headers\n\nFrom ..", the second \n belongs to next
		   message which we didn't know at the time yet. */
		i_assert(rstream->body_offset ==
			 rstream->hdr_offset + rstream->mail_size + 1);
		rstream->body_offset =
			rstream->hdr_offset + rstream->mail_size;
	}
}

static ssize_t _read(struct _istream *stream)
{
	static const char *mbox_from = "\nFrom ";
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;
	const unsigned char *buf;
	const char *fromp;
	char *sender, eoh_char;
	time_t received_time;
	size_t i, pos, new_pos, from_start_pos;
	ssize_t ret = 0;

	i_assert(stream->istream.v_offset >= rstream->from_offset);

	if (rstream->eom) {
		if (rstream->body_offset == (uoff_t)-1) {
			/* missing \n from headers */
			rstream->body_offset =
				stream->istream.v_offset +
				(stream->pos - stream->skip);
		}
		return -1;
	}

	i_stream_seek(rstream->input, stream->istream.v_offset);

	stream->pos -= stream->skip;
	stream->skip = 0;
	stream->buffer = NULL;

	do {
		ret = i_stream_read(rstream->input);
		buf = i_stream_get_data(rstream->input, &pos);
	} while (ret > 0 && (pos == 1 ||
			     stream->istream.v_offset + pos <=
			     rstream->input_peak_offset));

	if (ret < 0) {
		if (ret == -2)
			return -2;

		/* we've read the whole file, final byte should be
		   the \n trailer */
		if (pos > 0 && buf[pos-1] == '\n')
			pos--;

		i_assert(pos >= stream->pos);
		ret = pos == stream->pos ? -1 :
			(ssize_t)(pos - stream->pos);

		stream->buffer = buf;
		stream->pos = pos;

		rstream->eom = TRUE;
		rstream->eof = TRUE;
		handle_end_of_mail(rstream, pos);
		return ret < 0 ? _read(stream) : ret;
	}

	if (stream->istream.v_offset == rstream->from_offset) {
		/* beginning of message, we haven't yet read our From-line */
		if (mbox_read_from_line(rstream) < 0) {
			stream->pos = 0;
			rstream->eof = TRUE;
			rstream->corrupted = TRUE;
			return -1;
		}

		/* got it. we don't want to return it however,
		   so start again from headers */
		buf = i_stream_get_data(rstream->input, &pos);
		if (pos == 0)
			return _read(stream);
	}

	/* See if we have From-line here - note that it works right only
	   because all characters are different in mbox_from. */
        fromp = mbox_from; from_start_pos = 0;
	eoh_char = rstream->body_offset == (uoff_t)-1 ? '\n' : '\0';
	for (i = 0; i < pos; i++) {
		if (buf[i] == eoh_char && i > 0 && buf[i-1] == '\n') {
			rstream->body_offset = stream->istream.v_offset + i + 1;
			eoh_char = '\0';
		}
		if (buf[i] == *fromp) {
			if (*++fromp == '\0') {
				/* potential From-line, see if we have the
				   rest of the line buffered.
				   FIXME: if From-line is longer than input
				   buffer, we break. probably irrelevant.. */
				i++;
				from_start_pos = i;
				fromp = mbox_from;
			} else if (from_start_pos != 0) {
				/* we have the whole From-line here now.
				   See if it's a valid one. */
				if (mbox_from_parse(buf + from_start_pos,
						    pos - from_start_pos,
						    &received_time,
						    &sender) == 0) {
					/* yep, we stop here. */
					rstream->next_received_time =
						received_time;
					i_free(rstream->next_sender);
					rstream->next_sender = sender;
					rstream->eom = TRUE;

                                        /* rewind "\nFrom " */
					from_start_pos -= 6;

					handle_end_of_mail(rstream,
							   from_start_pos);
					break;
				}
				from_start_pos = 0;
			}
		} else {
			fromp = mbox_from;
			if (buf[i] == *fromp)
				fromp++;
		}
	}

	/* we want to go at least one byte further next time */
	rstream->input_peak_offset = stream->istream.v_offset + i;

	if (from_start_pos != 0) {
		/* we're waiting for the \n at the end of From-line */
		new_pos = from_start_pos;
	} else {
		/* leave out the beginnings of potential From-line */
		new_pos = i - (fromp - mbox_from);
	}
	i_assert(new_pos > stream->pos);
	ret = new_pos - stream->pos;

	stream->buffer = buf;
	stream->pos = new_pos;
	return ret;
}

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;

	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
	stream->buffer = NULL;

        rstream->input_peak_offset = 0;
	rstream->eom = FALSE;
	rstream->eof = FALSE;
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

uoff_t istream_raw_mbox_get_body_offset(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;
	uoff_t offset;
	size_t pos;

	if (rstream->body_offset != (uoff_t)-1)
		return rstream->body_offset;

	offset = stream->v_offset;
	i_stream_seek(stream, rstream->hdr_offset);
	while (rstream->body_offset == (uoff_t)-1) {
		i_stream_get_data(stream, &pos);
		i_stream_skip(stream, pos);

		if (_read(&rstream->istream) < 0)
			break;
	}

	i_stream_seek(stream, offset);
	return rstream->body_offset;
}

uoff_t istream_raw_mbox_get_body_size(struct istream *stream, uoff_t body_size)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;
	const unsigned char *data;
	size_t size;

	i_assert(rstream->hdr_offset != (uoff_t)-1);
	i_assert(rstream->body_offset != (uoff_t)-1);

	if (rstream->mail_size != (uoff_t)-1) {
		return rstream->mail_size -
			(rstream->body_offset - rstream->hdr_offset);
	}

	if (body_size != (uoff_t)-1) {
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

	if (stream->v_offset != rstream->from_offset)
		i_stream_seek(stream, rstream->from_offset);
	i_stream_seek(rstream->input, rstream->from_offset);

        rstream->input_peak_offset = 0;
	rstream->eom = FALSE;
	rstream->eof = FALSE;
}

int istream_raw_mbox_seek(struct istream *stream, uoff_t offset)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;
	int check;

	rstream->corrupted = FALSE;
	rstream->eom = FALSE;
	rstream->eof = FALSE;
        rstream->input_peak_offset = 0;

	if (rstream->mail_size != (uoff_t)-1 &&
	    rstream->hdr_offset + rstream->mail_size == offset) {
		istream_raw_mbox_next(stream, (uoff_t)-1);
		return 0;
	}

	if (offset == rstream->from_offset) {
		/* back to beginning of current message */
		offset = rstream->hdr_offset;
		check = offset == 0;
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
		check = TRUE;
	}

	i_stream_seek(stream, offset);
	i_stream_seek(rstream->input, offset);

	if (check)
		(void)_read(&rstream->istream);
	return rstream->corrupted ? -1 : 0;
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

int istream_raw_mbox_is_eof(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	return rstream->eof;
}
