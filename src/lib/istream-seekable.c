/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "close-keep-errno.h"
#include "read-full.h"
#include "write-full.h"
#include "istream-internal.h"
#include "istream-concat.h"
#include "istream-seekable.h"

#include <unistd.h>

#define BUF_INITIAL_SIZE (1024*32)

struct seekable_istream {
	struct istream_private istream;

	char *temp_path;
	uoff_t write_peak;

	int (*fd_callback)(const char **path_r, void *context);
	void *context;

	buffer_t *buffer;
	struct istream **input, *cur_input;
	struct istream *fd_input;
	unsigned int cur_idx;
	int fd;
};

static void i_stream_seekable_close(struct iostream_private *stream)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	unsigned int i;

	sstream->fd = -1;
	if (sstream->fd_input != NULL)
		i_stream_close(sstream->fd_input);
	for (i = 0; sstream->input[i] != NULL; i++)
		i_stream_close(sstream->input[i]);
}

static void i_stream_seekable_destroy(struct iostream_private *stream)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	unsigned int i;

	if (sstream->buffer != NULL)
		buffer_free(&sstream->buffer);
	if (sstream->fd_input != NULL)
		i_stream_unref(&sstream->fd_input);
	for (i = 0; sstream->input[i] != NULL; i++)
		i_stream_unref(&sstream->input[i]);

	i_free(sstream->temp_path);
}

static void
i_stream_seekable_set_max_buffer_size(struct iostream_private *stream,
				      size_t max_size)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	unsigned int i;

	sstream->istream.max_buffer_size = max_size;
	if (sstream->fd_input != NULL)
		i_stream_set_max_buffer_size(sstream->fd_input, max_size);
	for (i = 0; sstream->input[i] != NULL; i++)
		i_stream_set_max_buffer_size(sstream->input[i], max_size);
}

static int copy_to_temp_file(struct seekable_istream *sstream)
{
	struct istream_private *stream = &sstream->istream;
	const char *path;
	const unsigned char *buffer;
	size_t size;
	int fd;

	fd = sstream->fd_callback(&path, sstream->context);
	if (fd == -1)
		return -1;

	/* copy our currently read buffer to it */
	if (write_full(fd, sstream->buffer->data, sstream->buffer->used) < 0) {
		if (!ENOSPACE(errno))
			i_error("write_full(%s) failed: %m", path);
		close_keep_errno(fd);
		return -1;
	}
	sstream->temp_path = i_strdup(path);
	sstream->write_peak = sstream->buffer->used;

	sstream->fd = fd;
	sstream->fd_input =
		i_stream_create_fd(fd, sstream->istream.max_buffer_size, TRUE);

	/* read back the data we just had in our buffer */
	i_stream_seek(sstream->fd_input, stream->istream.v_offset);
	for (;;) {
		buffer = i_stream_get_data(sstream->fd_input, &size);
		if (size >= stream->pos)
			break;

		if (i_stream_read(sstream->fd_input) <= 0) {
			i_error("istream-seekable: Couldn't read back "
				"in-memory input %s",
				i_stream_get_name(&stream->istream));
			i_stream_destroy(&sstream->fd_input);
			return -1;
		}
	}
	stream->buffer = buffer;
	stream->pos = size;
	buffer_free(&sstream->buffer);
	return 0;
}

static ssize_t read_more(struct seekable_istream *sstream)
{
	size_t size;
	ssize_t ret;

	if (sstream->cur_input == NULL) {
		sstream->istream.istream.eof = TRUE;
		return -1;
	}

	while ((ret = i_stream_read(sstream->cur_input)) < 0) {
		if (!sstream->cur_input->eof) {
			/* full / error */
			sstream->istream.istream.stream_errno =
				sstream->cur_input->stream_errno;
			return -1;
		}

		/* go to next stream */
		sstream->cur_input = sstream->input[sstream->cur_idx++];
		if (sstream->cur_input == NULL) {
			/* last one, EOF */
			sstream->istream.istream.eof = TRUE;
			return -1;
		}

		/* see if stream has pending data */
		(void)i_stream_get_data(sstream->cur_input, &size);
		if (size != 0)
			return size;
	}
	return ret;
}

static bool read_from_buffer(struct seekable_istream *sstream, ssize_t *ret_r)
{
	struct istream_private *stream = &sstream->istream;
	const unsigned char *data;
	size_t size, pos, offset;

	i_assert(stream->skip == 0);

	if (stream->istream.v_offset + stream->pos >= sstream->buffer->used) {
		/* need to read more */
		if (sstream->buffer->used >= stream->max_buffer_size)
			return FALSE;

		if (sstream->cur_input == NULL)
			size = 0;
		else
			(void)i_stream_get_data(sstream->cur_input, &size);
		if (size == 0) {
			/* read more to buffer */
			*ret_r = read_more(sstream);
			if (*ret_r <= 0)
				return TRUE;
		}

		/* we should have more now. */
		data = i_stream_get_data(sstream->cur_input, &size);
		i_assert(size > 0);
		buffer_append(sstream->buffer, data, size);
		i_stream_skip(sstream->cur_input, size);
	}

	offset = stream->istream.v_offset;
	stream->buffer = CONST_PTR_OFFSET(sstream->buffer->data, offset);
	pos = sstream->buffer->used - offset;

	*ret_r = pos - stream->pos;
	i_assert(*ret_r > 0);
	stream->pos = pos;
	return TRUE;
}

static int i_stream_seekable_write_failed(struct seekable_istream *sstream)
{
	struct istream_private *stream = &sstream->istream;
	void *data;

	i_assert(sstream->buffer == NULL);

	sstream->buffer =
		buffer_create_dynamic(default_pool, sstream->write_peak);
	data = buffer_append_space_unsafe(sstream->buffer, sstream->write_peak);

	if (pread_full(sstream->fd, data, sstream->write_peak, 0) < 0) {
		i_error("read(%s) failed: %m", sstream->temp_path);
		buffer_free(&sstream->buffer);
		return -1;
	}
	i_stream_destroy(&sstream->fd_input);
	(void)close(sstream->fd);
	sstream->fd = -1;

	stream->max_buffer_size = (size_t)-1;
	i_free_and_null(sstream->temp_path);
	return 0;
}

static ssize_t i_stream_seekable_read(struct istream_private *stream)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	const unsigned char *data;
	size_t size, pos;
	ssize_t ret;

	stream->buffer = CONST_PTR_OFFSET(stream->buffer, stream->skip);
	stream->pos -= stream->skip;
	stream->skip = 0;

	if (sstream->buffer != NULL) {
		if (read_from_buffer(sstream, &ret))
			return ret;

		/* copy everything to temp file and use it as the stream */
		if (copy_to_temp_file(sstream) < 0) {
			stream->max_buffer_size = (size_t)-1;
			if (!read_from_buffer(sstream, &ret))
				i_unreached();
			return ret;
		}
		i_assert(sstream->buffer == NULL);
	}

	i_assert(stream->istream.v_offset + stream->pos <= sstream->write_peak);
	if (stream->istream.v_offset + stream->pos == sstream->write_peak) {
		/* need to read more */
		ret = read_more(sstream);
		if (ret <= 0)
			return ret;

		/* save to our file */
		data = i_stream_get_data(sstream->cur_input, &size);
		ret = write(sstream->fd, data, size);
		if (ret <= 0) {
			if (ret < 0 && !ENOSPACE(errno)) {
				i_error("write_full(%s) failed: %m",
					sstream->temp_path);
			}
			if (i_stream_seekable_write_failed(sstream) < 0)
				return -1;
			if (!read_from_buffer(sstream, &ret))
				i_unreached();
			return ret;
		}
		i_stream_sync(sstream->fd_input);
		i_stream_skip(sstream->cur_input, ret);
		sstream->write_peak += ret;
	}

	i_stream_seek(sstream->fd_input, stream->istream.v_offset);
	ret = i_stream_read(sstream->fd_input);
	if (ret <= 0) {
		stream->istream.eof = sstream->fd_input->eof;
		stream->istream.stream_errno =
			sstream->fd_input->stream_errno;
	} else {
		ret = -2;
	}

	stream->buffer = i_stream_get_data(sstream->fd_input, &pos);
	stream->pos -= stream->skip;
	stream->skip = 0;

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) : ret;
	stream->pos = pos;
	return ret;
}

static void i_stream_seekable_seek(struct istream_private *stream,
				   uoff_t v_offset, bool mark ATTR_UNUSED)
{
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
}

static const struct stat *
i_stream_seekable_stat(struct istream_private *stream, bool exact)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	uoff_t old_offset;
	ssize_t ret;

	if (sstream->buffer != NULL) {
		/* we want to know the full size of the file, so read until
		   we're finished */
		old_offset = stream->istream.v_offset;
		do {
			i_stream_skip(&stream->istream,
				      stream->pos - stream->skip);
		} while ((ret = i_stream_seekable_read(stream)) > 0);

		if (ret == 0) {
			i_panic("i_stream_stat() used for non-blocking "
				"seekable stream");
		}
		i_stream_skip(&stream->istream, stream->pos - stream->skip);
		i_stream_seek(&stream->istream, old_offset);
	}

	if (sstream->fd_input != NULL) {
		/* using a file backed buffer, we can use real fstat() */
		return i_stream_stat(sstream->fd_input, exact);
	} else {
		/* buffer is completely in memory */
		i_assert(sstream->buffer != NULL);

		stream->statbuf.st_size = sstream->buffer->used;
		return &stream->statbuf;
	}
}

struct istream *
i_stream_create_seekable(struct istream *input[],
			 size_t max_buffer_size,
			 int (*fd_callback)(const char **path_r, void *context),
			 void *context)
{
	struct seekable_istream *sstream;
	const unsigned char *data;
	unsigned int count;
	size_t size;
	bool blocking = TRUE;

	/* If all input streams are seekable, use concat istream instead */
	for (count = 0; input[count] != NULL; count++) {
		if (!input[count]->seekable)
			break;
	}
	if (input[count] == NULL)
		return i_stream_create_concat(input);

	/* if any of the streams isn't blocking, set ourself also nonblocking */
	for (count = 0; input[count] != NULL; count++) {
		if (!input[count]->blocking)
			blocking = FALSE;
		i_stream_ref(input[count]);
	}
	i_assert(count != 0);

	sstream = i_new(struct seekable_istream, 1);
	sstream->fd_callback = fd_callback;
	sstream->context = context;
	sstream->buffer = buffer_create_dynamic(default_pool, BUF_INITIAL_SIZE);
        sstream->istream.max_buffer_size = max_buffer_size;
	sstream->fd = -1;

	sstream->input = i_new(struct istream *, count + 1);
	memcpy(sstream->input, input, sizeof(*input) * count);
	sstream->cur_input = sstream->input[0];

	/* initialize our buffer from first stream's pending data */
	data = i_stream_get_data(sstream->cur_input, &size);
	buffer_append(sstream->buffer, data, size);
	i_stream_skip(sstream->cur_input, size);

	sstream->istream.iostream.close = i_stream_seekable_close;
	sstream->istream.iostream.destroy = i_stream_seekable_destroy;
	sstream->istream.iostream.set_max_buffer_size =
		i_stream_seekable_set_max_buffer_size;

	sstream->istream.read = i_stream_seekable_read;
	sstream->istream.seek = i_stream_seekable_seek;
	sstream->istream.stat = i_stream_seekable_stat;

	sstream->istream.istream.readable_fd = FALSE;
	sstream->istream.istream.blocking = blocking;
	sstream->istream.istream.seekable = TRUE;
	return i_stream_create(&sstream->istream, NULL, -1);
}
