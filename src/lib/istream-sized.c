/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "istream-sized.h"

struct sized_istream {
	struct istream_private istream;

	istream_sized_callback_t *error_callback;
	void *error_context;

	uoff_t size;
	bool min_size_only;
};

static void i_stream_sized_destroy(struct iostream_private *stream)
{
	struct sized_istream *sstream = (struct sized_istream *)stream;
	uoff_t v_offset;

	v_offset = sstream->istream.parent_start_offset +
		sstream->istream.istream.v_offset;
	if (sstream->istream.parent->seekable ||
	    v_offset > sstream->istream.parent->v_offset) {
		/* get to same position in parent stream */
		i_stream_seek(sstream->istream.parent, v_offset);
	}
}

static const char *
i_stream_create_sized_default_error_callback(
	const struct istream_sized_error_data *data, void *context ATTR_UNUSED)
{
	if (data->v_offset + data->new_bytes < data->wanted_size) {
		return t_strdup_printf("Stream is smaller than expected "
			"(%"PRIuUOFF_T" < %"PRIuUOFF_T")",
			data->v_offset + data->new_bytes, data->wanted_size);
	} else {
		return t_strdup_printf("Stream is larger than expected "
			"(%"PRIuUOFF_T" > %"PRIuUOFF_T", eof=%d)",
			data->v_offset + data->new_bytes, data->wanted_size,
			data->eof ? 1 : 0);
	}
}

static ssize_t
i_stream_sized_parent_read(struct istream_private *stream, size_t *pos_r)
{
	ssize_t ret;

	do {
		ret = i_stream_read_memarea(stream->parent);
		stream->istream.stream_errno = stream->parent->stream_errno;
		stream->istream.eof = stream->parent->eof;
		stream->buffer = i_stream_get_data(stream->parent, pos_r);
	} while (*pos_r <= stream->pos && ret > 0);
	return ret;
}

static ssize_t i_stream_sized_read(struct istream_private *stream)
{
	struct sized_istream *sstream =
		(struct sized_istream *)stream;
	struct istream_sized_error_data data;
	const char *error;
	uoff_t left;
	ssize_t ret;
	size_t pos;

	i_stream_seek(stream->parent, sstream->istream.parent_start_offset +
		      stream->istream.v_offset);

	stream->pos -= stream->skip;
	stream->skip = 0;

	stream->buffer = i_stream_get_data(stream->parent, &pos);
	if (pos > stream->pos)
		ret = 0;
	else {
		if ((ret = i_stream_sized_parent_read(stream, &pos)) == -2)
			return -2;
	}

	left = sstream->size - stream->istream.v_offset;
	if (pos == left && ret != -1) {
		/* we have exactly the wanted amount of data left, but we
		   don't know yet if there is more data in parent. */
		ret = i_stream_sized_parent_read(stream, &pos);
	}

	i_zero(&data);
	data.v_offset = stream->istream.v_offset;
	data.new_bytes = pos;
	data.wanted_size = sstream->size;
	data.eof = stream->istream.eof;

	if (pos == left) {
		/* we may or may not be finished, depending on whether
		   parent is at EOF. */
	} else if (pos > left) {
		/* parent has more data available than expected */
		if (!sstream->min_size_only) {
			error = sstream->error_callback(&data, sstream->error_context);
			io_stream_set_error(&stream->iostream, "%s", error);
			stream->istream.stream_errno = EINVAL;
			return -1;
		}
		pos = left;
		if (pos <= stream->pos) {
			stream->istream.eof = TRUE;
			ret = -1;
		}
	} else if (!stream->istream.eof) {
		/* still more to read */
	} else if (stream->istream.stream_errno == ENOENT) {
		/* lost the file */
	} else {
		/* EOF before we reached the wanted size */
		error = sstream->error_callback(&data, sstream->error_context);
		io_stream_set_error(&stream->iostream, "%s", error);
		stream->istream.stream_errno = EPIPE;
	}

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = pos;
	i_assert(ret != -1 || stream->istream.eof ||
		 stream->istream.stream_errno != 0);
	return ret;
}

static int
i_stream_sized_stat(struct istream_private *stream, bool exact ATTR_UNUSED)
{
	struct sized_istream *sstream = (struct sized_istream *)stream;
	const struct stat *st;

	/* parent stream may be base64-decoder. don't waste time decoding the
	   entire stream, since we already know what the size is supposed
	   to be. */
	if (i_stream_stat(stream->parent, FALSE, &st) < 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		return -1;
	}

	stream->statbuf = *st;
	stream->statbuf.st_size = sstream->size;
	return 0;
}

static struct sized_istream *
i_stream_create_sized_common(struct istream *input, uoff_t size)
{
	struct sized_istream *sstream;

	sstream = i_new(struct sized_istream, 1);
	sstream->size = size;
	sstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	sstream->istream.iostream.destroy = i_stream_sized_destroy;
	sstream->istream.read = i_stream_sized_read;
	sstream->istream.stat = i_stream_sized_stat;

	sstream->istream.istream.readable_fd = input->readable_fd;
	sstream->istream.istream.blocking = input->blocking;
	sstream->istream.istream.seekable = input->seekable;
	(void)i_stream_create(&sstream->istream, input,
			      i_stream_get_fd(input), 0);
	return sstream;
}

struct istream *i_stream_create_sized(struct istream *input, uoff_t size)
{
	struct sized_istream *sstream;

	sstream = i_stream_create_sized_common(input, size);
	sstream->error_callback = i_stream_create_sized_default_error_callback;
	sstream->error_context = sstream;
	return &sstream->istream.istream;
}

struct istream *i_stream_create_sized_range(struct istream *input,
					    uoff_t offset, uoff_t size)
{
	uoff_t orig_offset = input->v_offset;
	struct istream *ret;

	input->v_offset = offset;
	ret = i_stream_create_sized(input, size);
	input->v_offset = orig_offset;
	return ret;
}

struct istream *i_stream_create_min_sized(struct istream *input, uoff_t min_size)
{
	struct istream *ret;

	ret= i_stream_create_sized(input, min_size);
	((struct sized_istream *)ret->real_stream)->min_size_only = TRUE;
	return ret;
}

struct istream *i_stream_create_min_sized_range(struct istream *input,
						uoff_t offset, uoff_t min_size)
{
	struct istream *ret;

	ret = i_stream_create_sized_range(input, offset, min_size);
	((struct sized_istream *)ret->real_stream)->min_size_only = TRUE;
	return ret;
}

#undef i_stream_create_sized_with_callback
struct istream *
i_stream_create_sized_with_callback(struct istream *input, uoff_t size,
				    istream_sized_callback_t *error_callback,
				    void *context)
{
	struct sized_istream *sstream;

	sstream = i_stream_create_sized_common(input, size);
	sstream->error_callback = error_callback;
	sstream->error_context = context;
	return &sstream->istream.istream;
}
