/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"
#include "istream-attachment.h"

struct attachment_istream {
	struct istream_private istream;

	uoff_t size;
};

static ssize_t i_stream_attachment_read(struct istream_private *stream)
{
	struct attachment_istream *astream =
		(struct attachment_istream *)stream;
	uoff_t left;
	ssize_t ret;
	size_t pos;

	if (stream->istream.v_offset +
	    (stream->pos - stream->skip) >= astream->size) {
		stream->istream.eof = TRUE;
		return -1;
	}

	i_stream_seek(stream->parent, astream->istream.parent_start_offset +
		      stream->istream.v_offset);

	stream->pos -= stream->skip;
	stream->skip = 0;

	stream->buffer = i_stream_get_data(stream->parent, &pos);
	if (pos > stream->pos)
		ret = 0;
	else do {
		if ((ret = i_stream_read(stream->parent)) == -2)
			return -2;

		stream->istream.stream_errno = stream->parent->stream_errno;
		stream->istream.eof = stream->parent->eof;
		stream->buffer = i_stream_get_data(stream->parent, &pos);
	} while (pos <= stream->pos && ret > 0);

	left = astream->size - stream->istream.v_offset;
	if (pos == left)
		stream->istream.eof = TRUE;
	else if (pos > left) {
		i_error("Attachment file %s larger than expected "
			"(%"PRIuUOFF_T")", i_stream_get_name(stream->parent),
			astream->size);
		pos = left;
		stream->istream.eof = TRUE;
	} else if (!stream->istream.eof) {
		/* still more to read */
	} else if (stream->istream.stream_errno == ENOENT) {
		/* lost the file */
	} else {
		i_error("Attachment file %s smaller than expected "
			"(%"PRIuUOFF_T" < %"PRIuUOFF_T")",
			i_stream_get_name(stream->parent),
			stream->istream.v_offset, astream->size);
		stream->istream.stream_errno = EIO;
	}

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = pos;
	i_assert(ret != -1 || stream->istream.eof ||
		 stream->istream.stream_errno != 0);
	return ret;
}

static void
i_stream_attachment_seek(struct istream_private *stream,
			 uoff_t v_offset, bool mark ATTR_UNUSED)
{
	struct attachment_istream *astream =
		(struct attachment_istream *)stream;

	i_assert(v_offset <= astream->size);

	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
}

static const struct stat *
i_stream_attachment_stat(struct istream_private *stream, bool exact ATTR_UNUSED)
{
	struct attachment_istream *astream =
		(struct attachment_istream *)stream;
	const struct stat *st;

	/* parent stream may be base64-decoder. don't waste time decoding the
	   entire stream, since we already know what the size is supposed
	   to be. */
	st = i_stream_stat(stream->parent, FALSE);
	if (st == NULL)
		return NULL;

	stream->statbuf = *st;
	stream->statbuf.st_size = astream->size;
	return &stream->statbuf;
}

struct istream *i_stream_create_attachment(struct istream *input, uoff_t size)
{
	struct attachment_istream *astream;

	astream = i_new(struct attachment_istream, 1);
	astream->size = size;
	astream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	astream->istream.parent = input;
	astream->istream.read = i_stream_attachment_read;
	astream->istream.seek = i_stream_attachment_seek;
	astream->istream.stat = i_stream_attachment_stat;

	astream->istream.istream.readable_fd = input->readable_fd;
	astream->istream.istream.blocking = input->blocking;
	astream->istream.istream.seekable = input->seekable;
	return i_stream_create(&astream->istream, input,
			       i_stream_get_fd(input));
}
