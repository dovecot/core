/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream-private.h"
#include "istream-concat.h"

struct concat_istream {
	struct istream_private istream;

	struct istream **input, *cur_input;
	uoff_t *input_size;

	unsigned int cur_idx, unknown_size_idx;
	size_t prev_stream_left, prev_skip;
};

static void i_stream_concat_close(struct iostream_private *stream,
				  bool close_parent)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	unsigned int i;

	if (close_parent) {
		for (i = 0; cstream->input[i] != NULL; i++)
			i_stream_close(cstream->input[i]);
	}
}

static void i_stream_concat_destroy(struct iostream_private *stream)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	unsigned int i;

	for (i = 0; cstream->input[i] != NULL; i++)
		i_stream_unref(&cstream->input[i]);
	i_free(cstream->input);
	i_free(cstream->input_size);
	i_free(cstream->istream.w_buffer);
}

static void
i_stream_concat_set_max_buffer_size(struct iostream_private *stream,
				    size_t max_size)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	unsigned int i;

	cstream->istream.max_buffer_size = max_size;
	for (i = 0; cstream->input[i] != NULL; i++)
		i_stream_set_max_buffer_size(cstream->input[i], max_size);
}

static void i_stream_concat_read_next(struct concat_istream *cstream)
{
	const unsigned char *data;
	size_t data_size, size;

	i_assert(cstream->cur_input->eof);

	data = i_stream_get_data(cstream->cur_input, &data_size);
	cstream->cur_idx++;
	cstream->cur_input = cstream->input[cstream->cur_idx];
	i_stream_seek(cstream->cur_input, 0);

	if (cstream->prev_stream_left > 0 || cstream->istream.pos == 0) {
		cstream->prev_stream_left += data_size;
		i_assert(cstream->prev_stream_left ==
			 cstream->istream.pos - cstream->istream.skip);
		return;
	}

	/* we already verified that the data size is less than the
	   maximum buffer size */
	cstream->istream.pos = 0;
	if (data_size > 0) {
		if (!i_stream_try_alloc(&cstream->istream, data_size, &size))
			i_unreached();
		i_assert(size >= data_size);
	}

	cstream->prev_stream_left = data_size;
	memcpy(cstream->istream.w_buffer, data, data_size);
	cstream->istream.skip = 0;
	cstream->istream.pos = data_size;
}

static ssize_t i_stream_concat_read(struct istream_private *stream)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	const unsigned char *data;
	size_t size, data_size, cur_data_pos, new_pos, bytes_skipped;
	size_t new_bytes_count;
	ssize_t ret;
	bool last_stream;

	if (cstream->cur_input == NULL) {
		stream->istream.stream_errno = EINVAL;
		return -1;
	}

	i_assert(stream->skip >= cstream->prev_skip);
	bytes_skipped = stream->skip - cstream->prev_skip;

	if (cstream->prev_stream_left == 0) {
		/* no need to worry about buffers, skip everything */
	} else if (bytes_skipped < cstream->prev_stream_left) {
		/* we're still skipping inside buffer */
		cstream->prev_stream_left -= bytes_skipped;
		bytes_skipped = 0;
	} else {
		/* done with the buffer */
		bytes_skipped -= cstream->prev_stream_left;
		cstream->prev_stream_left = 0;
	}
	stream->pos -= bytes_skipped;
	stream->skip -= bytes_skipped;
	stream->buffer += bytes_skipped;
	cstream->prev_skip = stream->skip;
	i_stream_skip(cstream->cur_input, bytes_skipped);

	i_assert(stream->pos >= stream->skip + cstream->prev_stream_left);
	cur_data_pos = stream->pos - (stream->skip + cstream->prev_stream_left);

	data = i_stream_get_data(cstream->cur_input, &data_size);
	if (data_size > cur_data_pos)
		ret = 0;
	else {
		/* need to read more */
		i_assert(cur_data_pos == data_size);
		ret = i_stream_read(cstream->cur_input);
		if (ret == -2 || ret == 0)
			return ret;

		if (ret == -1 && cstream->cur_input->stream_errno != 0) {
			stream->istream.stream_errno =
				cstream->cur_input->stream_errno;
			return -1;
		}

		/* we either read something or we're at EOF */
		last_stream = cstream->input[cstream->cur_idx+1] == NULL;
		if (ret == -1 && !last_stream) {
			if (stream->pos >= stream->max_buffer_size)
				return -2;

			i_stream_concat_read_next(cstream);
			cstream->prev_skip = stream->skip;
			return i_stream_concat_read(stream);
		}

		stream->istream.eof = cstream->cur_input->eof && last_stream;
		i_assert(ret != -1 || stream->istream.eof);
		data = i_stream_get_data(cstream->cur_input, &data_size);
	}

	if (cstream->prev_stream_left == 0) {
		/* we can point directly to the current stream's buffers */
		stream->buffer = data;
		stream->pos -= stream->skip;
		stream->skip = 0;
		new_pos = data_size;
	} else if (data_size == cur_data_pos) {
		/* nothing new read */
		i_assert(ret == 0 || ret == -1);
		stream->buffer = stream->w_buffer;
		new_pos = stream->pos;
	} else {
		/* we still have some of the previous stream left. merge the
		   new data with it. */
		i_assert(data_size > cur_data_pos);
		new_bytes_count = data_size - cur_data_pos;
		if (!i_stream_try_alloc(stream, new_bytes_count, &size)) {
			stream->buffer = stream->w_buffer;
			return -2;
		}
		stream->buffer = stream->w_buffer;

		if (new_bytes_count > size)
			new_bytes_count = size;
		memcpy(stream->w_buffer + stream->pos,
		       data + cur_data_pos, new_bytes_count);
		new_pos = stream->pos + new_bytes_count;
	}

	ret = new_pos > stream->pos ? (ssize_t)(new_pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = new_pos;
	cstream->prev_skip = stream->skip;
	return ret;
}

static unsigned int
find_v_offset(struct concat_istream *cstream, uoff_t *v_offset)
{
	const struct stat *st;
	unsigned int i;

	for (i = 0; cstream->input[i] != NULL; i++) {
		if (*v_offset == 0) {
			/* seek to beginning of this stream */
			break;
		}
		if (i == cstream->unknown_size_idx) {
			/* we'll need to figure out this stream's size */
			if (i_stream_stat(cstream->input[i], TRUE, &st) < 0) {
				i_error("istream-concat: "
					"Failed to get size of stream %s",
					i_stream_get_name(cstream->input[i]));
				cstream->istream.istream.stream_errno =
					cstream->input[i]->stream_errno;
				return UINT_MAX;
			}

			/* @UNSAFE */
			cstream->input_size[i] = st->st_size;
			cstream->unknown_size_idx = i + 1;
		}
		if (*v_offset < cstream->input_size[i])
			break;
		*v_offset -= cstream->input_size[i];
	}

	return i;
}

static void i_stream_concat_seek(struct istream_private *stream,
				 uoff_t v_offset, bool mark ATTR_UNUSED)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;

	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
	cstream->prev_stream_left = 0;
	cstream->prev_skip = 0;

	cstream->cur_idx = find_v_offset(cstream, &v_offset);
	if (cstream->cur_idx == UINT_MAX) {
		/* failed */
		cstream->cur_input = NULL;
		stream->istream.stream_errno = EINVAL;
		return;
	}
	cstream->cur_input = cstream->input[cstream->cur_idx];
	if (cstream->cur_input != NULL)
		i_stream_seek(cstream->cur_input, v_offset);
}

static int
i_stream_concat_stat(struct istream_private *stream, bool exact ATTR_UNUSED)
{
	struct concat_istream *cstream = (struct concat_istream *)stream;
	uoff_t v_offset = (uoff_t)-1;
	unsigned int i;

	/* make sure we have all sizes */
	if (find_v_offset(cstream, &v_offset) == UINT_MAX)
		return -1;

	stream->statbuf.st_size = 0;
	for (i = 0; i < cstream->unknown_size_idx; i++)
		stream->statbuf.st_size += cstream->input_size[i];
	return 0;
}

struct istream *i_stream_create_concat(struct istream *input[])
{
	struct concat_istream *cstream;
	unsigned int count;
	size_t max_buffer_size = I_STREAM_MIN_SIZE;
	bool blocking = TRUE, seekable = TRUE;

	/* if any of the streams isn't blocking or seekable, set ourself also
	   nonblocking/nonseekable */
	for (count = 0; input[count] != NULL; count++) {
		size_t cur_max = input[count]->real_stream->max_buffer_size;

		if (cur_max > max_buffer_size)
			max_buffer_size = cur_max;
		if (!input[count]->blocking)
			blocking = FALSE;
		if (!input[count]->seekable)
			seekable = FALSE;
		i_stream_ref(input[count]);
	}
	i_assert(count != 0);

	cstream = i_new(struct concat_istream, 1);
	cstream->input = i_new(struct istream *, count + 1);
	cstream->input_size = i_new(uoff_t, count + 1);

	memcpy(cstream->input, input, sizeof(*input) * count);
	cstream->cur_input = cstream->input[0];
	i_stream_seek(cstream->cur_input, 0);

	cstream->istream.iostream.close = i_stream_concat_close;
	cstream->istream.iostream.destroy = i_stream_concat_destroy;
	cstream->istream.iostream.set_max_buffer_size =
		i_stream_concat_set_max_buffer_size;

	cstream->istream.max_buffer_size = max_buffer_size;
	cstream->istream.read = i_stream_concat_read;
	cstream->istream.seek = i_stream_concat_seek;
	cstream->istream.stat = i_stream_concat_stat;

	cstream->istream.istream.readable_fd = FALSE;
	cstream->istream.istream.blocking = blocking;
	cstream->istream.istream.seekable = seekable;
	return i_stream_create(&cstream->istream, NULL, -1);
}
