/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "test-common.h"

struct test_istream {
	struct istream_private istream;
	const void *orig_buffer;
	unsigned int skip_diff;
	size_t max_pos;
	bool allow_eof;
};

static ssize_t test_read(struct istream_private *stream)
{
	struct test_istream *tstream = (struct test_istream *)stream;
	unsigned int new_skip_diff;
	size_t cur_max;
	ssize_t ret;

	i_assert(stream->skip <= stream->pos);

	if (stream->pos - stream->skip >= tstream->istream.max_buffer_size) {
		i_assert(stream->skip != stream->pos);
		return -2;
	}

	if (tstream->max_pos < stream->pos) {
		/* we seeked past the end of file. */
		ret = 0;
	} else {
		/* copy data to a buffer in somewhat random place. this could
		   help catch bugs. */
		new_skip_diff = rand() % 128;
		stream->skip = (stream->skip - tstream->skip_diff) +
			new_skip_diff;
		stream->pos = (stream->pos - tstream->skip_diff) +
			new_skip_diff;
		tstream->max_pos = (tstream->max_pos - tstream->skip_diff) +
			new_skip_diff;
		tstream->skip_diff = new_skip_diff;

		cur_max = tstream->max_pos;
		if (stream->max_buffer_size < (size_t)-1 - stream->skip &&
		    cur_max > stream->skip + stream->max_buffer_size)
			cur_max = stream->skip + stream->max_buffer_size;

		/* use exactly correct buffer size so valgrind can catch
		   read overflows */
		if (stream->buffer_size != cur_max && cur_max > 0) {
			stream->w_buffer = i_realloc(stream->w_buffer,
						     stream->buffer_size,
						     cur_max);
			stream->buffer = stream->w_buffer;
			stream->buffer_size = cur_max;
		}
		ssize_t size = cur_max - new_skip_diff;
		if (size > 0)
			memcpy(stream->w_buffer + new_skip_diff,
				tstream->orig_buffer, (size_t)size);

		ret = cur_max - stream->pos;
		stream->pos = cur_max;
	}

	if (ret > 0)
		return ret;
	else if (!tstream->allow_eof ||
		 stream->pos - tstream->skip_diff < (uoff_t)stream->statbuf.st_size)
		return 0;
	else {
		stream->istream.eof = TRUE;
		return -1;
	}
}

static void test_seek(struct istream_private *stream, uoff_t v_offset,
		      bool mark ATTR_UNUSED)
{
	struct test_istream *tstream = (struct test_istream *)stream;

	stream->istream.v_offset = v_offset;
	stream->skip = v_offset + tstream->skip_diff;
	stream->pos = stream->skip;
}

struct istream *test_istream_create_data(const void *data, size_t size)
{
	struct test_istream *tstream;

	tstream = i_new(struct test_istream, 1);
	tstream->orig_buffer = data;

	tstream->istream.read = test_read;
	tstream->istream.seek = test_seek;

	tstream->istream.istream.blocking = FALSE;
	tstream->istream.istream.seekable = TRUE;
	i_stream_create(&tstream->istream, NULL, -1);
	tstream->istream.statbuf.st_size = tstream->max_pos = size;
	tstream->allow_eof = TRUE;
	tstream->istream.max_buffer_size = (size_t)-1;
	return &tstream->istream.istream;
}

struct istream *test_istream_create(const char *data)
{
	return test_istream_create_data(data, strlen(data));
}

static struct test_istream *test_istream_find(struct istream *input)
{
	struct istream *in;

	for (in = input; in != NULL; in = in->real_stream->parent) {
		if (in->real_stream->read == test_read)
			return (struct test_istream *)in->real_stream;
	}
	i_panic("%s isn't test-istream", i_stream_get_name(input));
}

void test_istream_set_allow_eof(struct istream *input, bool allow)
{
	struct test_istream *tstream = test_istream_find(input);

	tstream->allow_eof = allow;
}

void test_istream_set_max_buffer_size(struct istream *input, size_t size)
{
	struct test_istream *tstream = test_istream_find(input);

	tstream->istream.max_buffer_size = size;
}

void test_istream_set_size(struct istream *input, uoff_t size)
{
	struct test_istream *tstream = test_istream_find(input);

	if (size > (uoff_t)tstream->istream.statbuf.st_size)
		size = (uoff_t)tstream->istream.statbuf.st_size;
	tstream->max_pos = size + tstream->skip_diff;
}
