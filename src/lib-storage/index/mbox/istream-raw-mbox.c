/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream-internal.h"
#include "istream-raw-mbox.h"
#include "mbox-from.h"

struct raw_mbox_istream {
	struct istream_private istream;

	time_t received_time, next_received_time;
	char *sender, *next_sender;

	uoff_t from_offset, hdr_offset, body_offset, mail_size;
	uoff_t input_peak_offset;

	unsigned int locked:1;
	unsigned int seeked:1;
	unsigned int crlf_ending:1;
	unsigned int corrupted:1;
	unsigned int mail_size_forced:1;
	unsigned int eof:1;
	unsigned int header_missing_eoh:1;
};

static void i_stream_raw_mbox_destroy(struct iostream_private *stream)
{
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;

	i_free(rstream->sender);
	i_free(rstream->next_sender);

	i_stream_seek(rstream->istream.parent,
		      rstream->istream.istream.v_offset);
	i_stream_unref(&rstream->istream.parent);
}

static int mbox_read_from_line(struct raw_mbox_istream *rstream)
{
	const unsigned char *buf, *p;
	char *sender;
	time_t received_time;
	size_t pos, line_pos;
	ssize_t ret;
	unsigned int skip;
	int tz;

	buf = i_stream_get_data(rstream->istream.parent, &pos);
	i_assert(pos > 0);

	/* from_offset points to "\nFrom ", so unless we're at the beginning
	   of the file, skip the initial \n */
	if (rstream->from_offset == 0)
		skip = 0;
	else {
		skip = 1;
		if (*buf == '\r')
			skip++;
	}

	while ((p = memchr(buf+skip, '\n', pos-skip)) == NULL) {
		ret = i_stream_read(rstream->istream.parent);
		buf = i_stream_get_data(rstream->istream.parent, &pos);
		if (ret < 0) {
			if (ret == -2) {
				/* From_-line is too long, but we should be
				   able to parse what we have so far. */
				break;
			}
			/* EOF shouldn't happen */
			rstream->istream.istream.eof =
				rstream->istream.parent->eof;
			rstream->istream.istream.stream_errno =
				rstream->istream.parent->stream_errno;
			return -1;
		}
		i_assert(pos > 0);
	}
	line_pos = p == NULL ? 0 : (size_t)(p - buf);

	/* beginning of mbox */
	if (memcmp(buf+skip, "From ", 5) != 0 ||
	    mbox_from_parse((buf+skip)+5, (pos-skip)-5,
			    &received_time, &tz, &sender) < 0) {
		/* broken From - should happen only at beginning of
		   file if this isn't a mbox.. */
		rstream->istream.istream.stream_errno = EINVAL;
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

	/* skip over From-line */
	if (line_pos == 0) {
		/* line was too long. skip the input until we find LF. */
		rstream->istream.istream.v_offset += pos;
		i_stream_skip(rstream->istream.parent, pos);

		while ((ret = i_stream_read(rstream->istream.parent)) > 0) {
			p = memchr(buf, '\n', pos);
			if (p != NULL)
				break;
			rstream->istream.istream.v_offset += pos;
			i_stream_skip(rstream->istream.parent, pos);
		}
		if (ret <= 0) {
			i_assert(ret == -1);
			/* EOF shouldn't happen */
			rstream->istream.istream.eof =
				rstream->istream.parent->eof;
			rstream->istream.istream.stream_errno =
				rstream->istream.parent->stream_errno;
			return -1;
		}
		line_pos = (size_t)(p - buf);
	}
	rstream->istream.istream.v_offset += line_pos+1;
	i_stream_skip(rstream->istream.parent, line_pos+1);

	rstream->hdr_offset = rstream->istream.istream.v_offset;
	return 0;
}

static void handle_end_of_mail(struct raw_mbox_istream *rstream, size_t pos)
{
	rstream->mail_size = rstream->istream.istream.v_offset + pos -
		rstream->hdr_offset;

	if (rstream->hdr_offset + rstream->mail_size < rstream->body_offset) {
		uoff_t new_body_offset =
			rstream->hdr_offset + rstream->mail_size;

		if (rstream->body_offset != (uoff_t)-1) {
			/* Header didn't have ending \n */
			rstream->header_missing_eoh = TRUE;
		} else {
			/* "headers\n\nFrom ..", the second \n belongs to next
			   message which we didn't know at the time yet. */
		}

		/* The +2 check is for CR+LF linefeeds */
		i_assert(rstream->body_offset == (uoff_t)-1 ||
			 rstream->body_offset == new_body_offset + 1 ||
			 rstream->body_offset == new_body_offset + 2);
		rstream->body_offset = new_body_offset;
	}
}

static ssize_t i_stream_raw_mbox_read(struct istream_private *stream)
{
	static const char *mbox_from = "\nFrom ";
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;
	const unsigned char *buf;
	const char *fromp;
	char *sender;
	time_t received_time;
	size_t i, pos, new_pos, from_start_pos, from_after_pos;
	ssize_t ret = 0;
	int eoh_char, tz;
	bool crlf_ending = FALSE;

	i_assert(rstream->seeked);
	i_assert(stream->istream.v_offset >= rstream->from_offset);

	if (stream->istream.eof)
		return -1;
	if (rstream->corrupted) {
		rstream->istream.istream.stream_errno = EINVAL;
		return -1;
	}

	i_stream_seek(stream->parent, stream->istream.v_offset);

	stream->pos -= stream->skip;
	stream->skip = 0;
	stream->buffer = NULL;

	do {
		buf = i_stream_get_data(stream->parent, &pos);
		if (pos > 1 && stream->istream.v_offset + pos >
		    rstream->input_peak_offset) {
			/* fake our read count. needed because if in the end
			   we have only one character in buffer and we skip it
			   (as potential CR), we want to get back to this
			   i_stream_raw_mbox_read() to read more data. */
			ret = pos;
			break;
		}
		ret = i_stream_read(stream->parent);
	} while (ret > 0);
	stream->istream.stream_errno = stream->parent->stream_errno;

	if (ret < 0) {
		if (ret == -2) {
			if (stream->skip == stream->pos) {
				/* From_-line is longer than our input buffer.
				   finish the check without seeing the LF. */
			} else if (stream->istream.v_offset + pos ==
				   rstream->input_peak_offset) {
				/* we've read everything our parent stream
				   has to offer. */
				stream->buffer = buf;
				return -2;
			}
			/* parent stream is full, but we haven't returned
			   all its bytes to our caller yet. */
		} else if (stream->istream.v_offset != 0 || pos == 0) {
			/* we've read the whole file, final byte should be
			   the \n trailer */
			if (pos > 0 && buf[pos-1] == '\n') {
				pos--;
				if (pos > 0 && buf[pos-1] == '\r') {
					crlf_ending = TRUE;
					pos--;
				}
			}

			i_assert(pos >= stream->pos);
			ret = pos == stream->pos ? -1 :
				(ssize_t)(pos - stream->pos);

			stream->buffer = buf;
			stream->pos = pos;

			if (stream->istream.v_offset == rstream->from_offset) {
				/* haven't seen From-line yet, so this mbox
				   stream is now at EOF */
				rstream->eof = TRUE;
			}
			stream->istream.eof = TRUE;
			rstream->crlf_ending = crlf_ending;
			handle_end_of_mail(rstream, pos);
			return ret < 0 ? i_stream_raw_mbox_read(stream) : ret;
		}
	}

	if (stream->istream.v_offset == rstream->from_offset) {
		/* beginning of message, we haven't yet read our From-line */
		if (pos == 2 && ret > 0) {
			/* we're at the end of file with CR+LF linefeeds?
			   need more data to verify it. */
			rstream->input_peak_offset =
				stream->istream.v_offset + pos;
			return i_stream_raw_mbox_read(stream);
		}
		if (mbox_read_from_line(rstream) < 0) {
			if (stream->istream.v_offset != 0) {
				i_error("Next message unexpectedly corrupted in mbox file "
					"%s at %"PRIuUOFF_T,
					i_stream_get_name(&stream->istream),
					stream->istream.v_offset);
			}
			stream->pos = 0;
			rstream->eof = TRUE;
			rstream->corrupted = TRUE;
			return -1;
		}

		/* got it. we don't want to return it however,
		   so start again from headers */
		buf = i_stream_get_data(stream->parent, &pos);
		if (pos == 0)
			return i_stream_raw_mbox_read(stream);
	}

	/* See if we have From-line here - note that it works right only
	   because all characters are different in mbox_from. */
        fromp = mbox_from; from_start_pos = from_after_pos = (size_t)-1;
	eoh_char = rstream->body_offset == (uoff_t)-1 ? '\n' : -1;
	for (i = stream->pos; i < pos; i++) {
		if (buf[i] == eoh_char &&
		    ((i > 0 && buf[i-1] == '\n') ||
                     (i > 1 && buf[i-1] == '\r' && buf[i-2] == '\n') ||
		     stream->istream.v_offset + i == rstream->hdr_offset)) {
			rstream->body_offset = stream->istream.v_offset + i + 1;
			eoh_char = -1;
		}
		if ((char)buf[i] == *fromp) {
			if (*++fromp == '\0') {
				/* potential From-line, see if we have the
				   rest of the line buffered. */
				i++;
				if (i >= 7 && buf[i-7] == '\r') {
					/* CR also belongs to it. */
					crlf_ending = TRUE;
					from_start_pos = i - 7;
				} else {
					crlf_ending = FALSE;
					from_start_pos = i - 6;
				}

				if (rstream->hdr_offset + rstream->mail_size ==
				    stream->istream.v_offset + from_start_pos ||
				    rstream->mail_size == (uoff_t)-1) {
					from_after_pos = i;
					if (ret == -2) {
						/* even if we don't have the
						   whole line, we need to
						   finish this check now. */
						goto mbox_verify;
					}
				}
				fromp = mbox_from;
			} else if (from_after_pos != (size_t)-1) {
				/* we have the whole From-line here now.
				   See if it's a valid one. */
			mbox_verify:
				if (mbox_from_parse(buf + from_after_pos,
						    pos - from_after_pos,
						    &received_time, &tz,
						    &sender) == 0) {
					/* yep, we stop here. */
					rstream->next_received_time =
						received_time;
					i_free(rstream->next_sender);
					rstream->next_sender = sender;
					stream->istream.eof = TRUE;

					rstream->crlf_ending = crlf_ending;
					handle_end_of_mail(rstream,
							   from_start_pos);
					break;
				}
				from_after_pos = (size_t)-1;
			}
		} else {
			fromp = mbox_from;
			if ((char)buf[i] == *fromp)
				fromp++;
		}
	}

	/* we want to go at least one byte further next time */
	rstream->input_peak_offset = stream->istream.v_offset + i;

	if (from_after_pos != (size_t)-1) {
		/* we're waiting for the \n at the end of From-line */
		new_pos = from_start_pos;
	} else {
		/* leave out the beginnings of potential From-line + CR */
		new_pos = i - (fromp - mbox_from);
		if (new_pos > 0)
			new_pos--;
	}

	if (stream->istream.v_offset -
	    rstream->hdr_offset + new_pos > rstream->mail_size) {
		/* istream_raw_mbox_set_next_offset() used invalid
		   cached next_offset? */
		i_error("Next message unexpectedly lost from mbox file "
			"%s at %"PRIuUOFF_T" (%s)",
			i_stream_get_name(&stream->istream),
			rstream->hdr_offset + rstream->mail_size,
			rstream->mail_size_forced ? "cached" : "noncached");
		rstream->eof = TRUE;
		rstream->corrupted = TRUE;
		rstream->istream.istream.stream_errno = EINVAL;
		stream->pos = 0;
		return -1;
	}

	stream->buffer = buf;
	if (new_pos == stream->pos) {
		if (stream->istream.eof || ret > 0)
			return i_stream_raw_mbox_read(stream);
		i_assert(new_pos > 0);
		ret = -2;
	} else {
		i_assert(new_pos > stream->pos);
		ret = new_pos - stream->pos;
		stream->pos = new_pos;
	}
	return ret;
}

static void i_stream_raw_mbox_seek(struct istream_private *stream,
				   uoff_t v_offset, bool mark ATTR_UNUSED)
{
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;

	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
	stream->buffer = NULL;

        rstream->input_peak_offset = 0;
	rstream->eof = FALSE;
}

static void i_stream_raw_mbox_sync(struct istream_private *stream)
{
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;

	i_stream_sync(stream->parent);

	rstream->istream.skip = 0;
	rstream->istream.pos = 0;
	rstream->input_peak_offset = 0;
}

static const struct stat *
i_stream_raw_mbox_stat(struct istream_private *stream, bool exact)
{
	const struct stat *st;
	struct raw_mbox_istream *rstream = (struct raw_mbox_istream *)stream;

	st = i_stream_stat(stream->parent, exact);
	if (st == NULL)
		return NULL;

	stream->statbuf = *st;
	stream->statbuf.st_size =
		!exact && rstream->seeked && rstream->mail_size != (uoff_t)-1 ?
		(off_t)rstream->mail_size : -1;
	return &stream->statbuf;
}

struct istream *i_stream_create_raw_mbox(struct istream *input)
{
	struct raw_mbox_istream *rstream;

	i_assert(input->v_offset == 0);

	rstream = i_new(struct raw_mbox_istream, 1);

	rstream->body_offset = (uoff_t)-1;
	rstream->mail_size = (uoff_t)-1;
	rstream->received_time = (time_t)-1;
	rstream->next_received_time = (time_t)-1;

	rstream->istream.iostream.destroy = i_stream_raw_mbox_destroy;
	rstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	rstream->istream.read = i_stream_raw_mbox_read;
	rstream->istream.seek = i_stream_raw_mbox_seek;
	rstream->istream.sync = i_stream_raw_mbox_sync;
	rstream->istream.stat = i_stream_raw_mbox_stat;

	rstream->istream.istream.readable_fd = input->readable_fd;
	rstream->istream.istream.blocking = input->blocking;
	rstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&rstream->istream, input, -1);
}

static int istream_raw_mbox_is_valid_from(struct raw_mbox_istream *rstream)
{
	const unsigned char *data;
	size_t size;
	time_t received_time;
	char *sender;
	int tz;

	/* minimal: "From x Thu Nov 29 22:33:52 2001" = 31 chars */
	(void)i_stream_read_data(rstream->istream.parent, &data, &size, 30);

	if ((size == 1 && data[0] == '\n') ||
	    (size == 2 && data[0] == '\r' && data[1] == '\n')) {
		/* EOF */
		return 1;
	}

	if (size > 31 && memcmp(data, "\nFrom ", 6) == 0) {
		data += 6;
		size -= 6;
	} else if (size > 32 && memcmp(data, "\r\nFrom ", 7) == 0) {
		data += 7;
		size -= 7;
	} else {
		return 0;
	}

	while (memchr(data, '\n', size) == NULL) {
		if (i_stream_read_data(rstream->istream.parent,
				       &data, &size, size) < 0)
			break;
	}

	if (mbox_from_parse(data, size, &received_time, &tz, &sender) < 0)
		return 0;

	rstream->next_received_time = received_time;
	i_free(rstream->next_sender);
	rstream->next_sender = sender;
	return 1;
}

uoff_t istream_raw_mbox_get_start_offset(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	i_assert(rstream->seeked);

	return rstream->from_offset;
}

uoff_t istream_raw_mbox_get_header_offset(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	i_assert(rstream->seeked);

	if (rstream->hdr_offset == rstream->from_offset)
		(void)i_stream_raw_mbox_read(&rstream->istream);

	if (rstream->corrupted) {
		i_error("Unexpectedly lost From-line from mbox file %s at "
			"%"PRIuUOFF_T, i_stream_get_name(stream),
			rstream->from_offset);
		return (uoff_t)-1;
	}

	return rstream->hdr_offset;
}

uoff_t istream_raw_mbox_get_body_offset(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;
	uoff_t offset;
	size_t pos;

	i_assert(rstream->seeked);

	if (rstream->body_offset != (uoff_t)-1)
		return rstream->body_offset;

	offset = stream->v_offset;
	i_stream_seek(stream, rstream->hdr_offset);
	while (rstream->body_offset == (uoff_t)-1) {
		i_stream_get_data(stream, &pos);
		i_stream_skip(stream, pos);

		if (i_stream_raw_mbox_read(&rstream->istream) < 0) {
			if (rstream->corrupted) {
				i_error("Unexpectedly lost From-line from mbox file "
					"%s at %"PRIuUOFF_T,
					i_stream_get_name(stream),
					rstream->from_offset);
			} else {
				i_assert(rstream->body_offset != (uoff_t)-1);
			}
			break;
		}
	}

	i_stream_seek(stream, offset);
	return rstream->body_offset;
}

uoff_t istream_raw_mbox_get_body_size(struct istream *stream,
				      uoff_t expected_body_size)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;
	const unsigned char *data;
	size_t size;
	uoff_t old_offset, body_size, next_body_offset;

	i_assert(rstream->seeked);
	i_assert(rstream->hdr_offset != (uoff_t)-1);

	(void)istream_raw_mbox_get_body_offset(stream);
	body_size = rstream->mail_size == (uoff_t)-1 ? (uoff_t)-1 :
		rstream->mail_size - (rstream->body_offset -
				      rstream->hdr_offset);
	old_offset = stream->v_offset;
	if (expected_body_size != (uoff_t)-1) {
		/* if we already have the existing body size, use it as long as
		   it's >= expected body_size. otherwise the previous parsing
		   may have stopped at a From_-line that belongs to the body. */
		if (body_size != (uoff_t)-1 && body_size >= expected_body_size)
			return body_size;

		next_body_offset = rstream->body_offset + expected_body_size;
		/* If header_missing_eoh is set, the message body begins with
		   a From_-line and the body_offset is pointing to the line
		   *before* the first line of the body, i.e. the empty line
		   separating the headers from the body. If that is the case,
		   we'll have to skip over the empty line to get the correct
		   next_body_offset. */
		if (rstream->header_missing_eoh) {
			i_assert(body_size == 0);
			next_body_offset += rstream->crlf_ending ? 2 : 1;
		}

		i_stream_seek(rstream->istream.parent, next_body_offset);
		if (istream_raw_mbox_is_valid_from(rstream) > 0) {
			rstream->mail_size =
				next_body_offset - rstream->hdr_offset;
			i_stream_seek(stream, old_offset);
			return expected_body_size;
		}
		/* invalid expected_body_size */
	}
	if (body_size != (uoff_t)-1)
		return body_size;

	/* have to read through the message body */
	while (i_stream_read_data(stream, &data, &size, 0) > 0)
		i_stream_skip(stream, size);
	i_stream_seek(stream, old_offset);

	i_assert(rstream->mail_size != (uoff_t)-1);
	return rstream->mail_size -
		(rstream->body_offset - rstream->hdr_offset);
}

time_t istream_raw_mbox_get_received_time(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	i_assert(rstream->seeked);

	if (rstream->received_time == (time_t)-1)
		(void)i_stream_raw_mbox_read(&rstream->istream);
	return rstream->received_time;
}

const char *istream_raw_mbox_get_sender(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	i_assert(rstream->seeked);

	if (rstream->sender == NULL)
		(void)i_stream_raw_mbox_read(&rstream->istream);
	return rstream->sender == NULL ? "" : rstream->sender;
}

bool istream_raw_mbox_has_crlf_ending(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	i_assert(rstream->seeked);

	return rstream->crlf_ending;
}

void istream_raw_mbox_next(struct istream *stream, uoff_t expected_body_size)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;
	uoff_t body_size;

	body_size = istream_raw_mbox_get_body_size(stream, expected_body_size);
	rstream->mail_size = (uoff_t)-1;

	rstream->received_time = rstream->next_received_time;
	rstream->next_received_time = (time_t)-1;

	i_free(rstream->sender);
	rstream->sender = rstream->next_sender;
	rstream->next_sender = NULL;

	rstream->from_offset = rstream->body_offset + body_size;
	rstream->hdr_offset = rstream->from_offset;
	rstream->body_offset = (uoff_t)-1;
	rstream->header_missing_eoh = FALSE;

	if (stream->v_offset != rstream->from_offset)
		i_stream_seek_mark(stream, rstream->from_offset);
	i_stream_seek_mark(rstream->istream.parent, rstream->from_offset);

	rstream->eof = FALSE;
	rstream->istream.istream.eof = FALSE;
}

int istream_raw_mbox_seek(struct istream *stream, uoff_t offset)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;
	bool check;

	i_assert(rstream->locked);

	rstream->corrupted = FALSE;
	rstream->eof = FALSE;
	rstream->istream.istream.eof = FALSE;

	/* if seeked is FALSE, we unlocked in the middle. don't try to use
	   any cached state then. */
	if (rstream->mail_size != (uoff_t)-1 && rstream->seeked &&
	    rstream->hdr_offset + rstream->mail_size == offset) {
		istream_raw_mbox_next(stream, (uoff_t)-1);
		return 0;
	}

	if (offset == rstream->from_offset && rstream->seeked) {
		/* back to beginning of current message */
		offset = rstream->hdr_offset;
		check = offset == 0;
	} else {
		rstream->body_offset = (uoff_t)-1;
		rstream->mail_size = (uoff_t)-1;
		rstream->received_time = (time_t)-1;
		rstream->next_received_time = (time_t)-1;
		rstream->header_missing_eoh = FALSE;

		i_free(rstream->sender);
		rstream->sender = NULL;
		i_free(rstream->next_sender);
		rstream->next_sender = NULL;

                rstream->from_offset = offset;
		rstream->hdr_offset = offset;
		check = TRUE;
	}
	rstream->seeked = TRUE;

	i_stream_seek_mark(stream, offset);
	i_stream_seek_mark(rstream->istream.parent, offset);

	if (check)
		(void)i_stream_raw_mbox_read(&rstream->istream);
	return rstream->corrupted ? -1 : 0;
}

void istream_raw_mbox_set_next_offset(struct istream *stream, uoff_t offset)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	i_assert(rstream->hdr_offset != (uoff_t)-1);

	rstream->mail_size_forced = TRUE;
	rstream->mail_size = offset - rstream->hdr_offset;
}

bool istream_raw_mbox_is_eof(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	return rstream->eof;
}

bool istream_raw_mbox_is_corrupted(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	return rstream->corrupted;
}

void istream_raw_mbox_set_locked(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	rstream->locked = TRUE;
}

void istream_raw_mbox_set_unlocked(struct istream *stream)
{
	struct raw_mbox_istream *rstream =
		(struct raw_mbox_istream *)stream->real_stream;

	rstream->locked = FALSE;
	rstream->seeked = FALSE;
}
