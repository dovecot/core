/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "memarea.h"
#include "read-full.h"
#include "write-full.h"
#include "safe-mkstemp.h"
#include "istream-private.h"
#include "istream-concat.h"
#include "istream-seekable.h"

#include <unistd.h>

#define BUF_INITIAL_SIZE (1024*32)

struct seekable_istream {
	struct istream_private istream;

	char *temp_path;
	uoff_t write_peak;
	uoff_t size;
	size_t buffer_peak;

	int (*fd_callback)(const char **path_r, void *context);
	void *context;

	struct istream **input, *cur_input;
	struct istream *fd_input;
	unsigned int cur_idx;
	int fd;
	bool free_context;
};

static void i_stream_seekable_close(struct iostream_private *stream,
				    bool close_parent ATTR_UNUSED)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;

	sstream->fd = -1;
	i_stream_close(sstream->fd_input);
}

static void unref_streams(struct seekable_istream *sstream)
{
	unsigned int i;

	for (i = 0; sstream->input[i] != NULL; i++)
		i_stream_unref(&sstream->input[i]);
}

static void i_stream_seekable_destroy(struct iostream_private *stream)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;

	i_stream_free_buffer(&sstream->istream);
	i_stream_unref(&sstream->fd_input);
	unref_streams(sstream);

	if (sstream->free_context)
		i_free(sstream->context);
	i_free(sstream->temp_path);
	i_free(sstream->input);
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
	i_assert(stream->pos <= sstream->buffer_peak);
	if (write_full(fd, stream->buffer, sstream->buffer_peak) < 0) {
		if (!ENOSPACE(errno))
			i_error("istream-seekable: write_full(%s) failed: %m", path);
		i_close_fd(&fd);
		return -1;
	}
	sstream->temp_path = i_strdup(path);
	sstream->write_peak = sstream->buffer_peak;

	sstream->fd = fd;
	sstream->fd_input = i_stream_create_fd_autoclose(&fd,
		I_MAX(stream->pos, sstream->istream.max_buffer_size));
	i_stream_set_name(sstream->fd_input, t_strdup_printf(
		"(seekable temp-istream for: %s)", i_stream_get_name(&stream->istream)));

	/* read back the data we just had in our buffer */
	for (;;) {
		buffer = i_stream_get_data(sstream->fd_input, &size);
		if (size >= stream->pos)
			break;

		ssize_t ret;
		if ((ret = i_stream_read_memarea(sstream->fd_input)) <= 0) {
			i_assert(ret != 0);
			i_assert(ret != -2);
			i_error("istream-seekable: Couldn't read back "
				"in-memory input %s: %s",
				i_stream_get_name(&stream->istream),
				i_stream_get_error(sstream->fd_input));
			i_stream_destroy(&sstream->fd_input);
			i_close_fd(&sstream->fd);
			return -1;
		}
	}
	/* Set the max buffer size only after we've already read everything
	   into memory. For example with istream-data it's possible that
	   more data exists in buffer than max_buffer_size. */
	i_stream_set_max_buffer_size(sstream->fd_input,
				     sstream->istream.max_buffer_size);
	stream->buffer = buffer;
	i_stream_free_buffer(&sstream->istream);
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

	while ((ret = i_stream_read_memarea(sstream->cur_input)) == -1) {
		if (sstream->cur_input->stream_errno != 0) {
			io_stream_set_error(&sstream->istream.iostream,
				"read(%s) failed: %s",
				i_stream_get_name(sstream->cur_input),
				i_stream_get_error(sstream->cur_input));
			sstream->istream.istream.eof = TRUE;
			sstream->istream.istream.stream_errno =
				sstream->cur_input->stream_errno;
			return -1;
		}

		/* go to next stream */
		sstream->cur_input = sstream->input[sstream->cur_idx++];
		if (sstream->cur_input == NULL) {
			/* last one, EOF */
			sstream->size = sstream->istream.istream.v_offset;
			sstream->istream.istream.eof = TRUE;
			/* Now that EOF is reached, the stream can't return 0
			   anymore. Callers can now use this stream in places
			   that assert that blocking==TRUE. */
			sstream->istream.istream.blocking = TRUE;
			unref_streams(sstream);
			return -1;
		}

		/* see if stream has pending data */
		size = i_stream_get_data_size(sstream->cur_input);
		if (size != 0)
			return size;
	}
	return ret;
}

static bool read_from_buffer(struct seekable_istream *sstream, ssize_t *ret_r)
{
	struct istream_private *stream = &sstream->istream;
	const unsigned char *data;
	size_t size, avail_size;

	if (stream->pos < sstream->buffer_peak) {
		/* This could be the first read() or we could have already
		   seeked backwards. */
		i_assert(stream->pos == 0 && stream->skip == 0);
		stream->skip = stream->istream.v_offset;
		stream->pos = sstream->buffer_peak;
		size = stream->pos - stream->skip;
	} else {
		/* need to read more */
		i_assert(stream->pos == sstream->buffer_peak);
		size = sstream->cur_input == NULL ? 0 :
			i_stream_get_data_size(sstream->cur_input);
		if (size == 0) {
			/* read more to buffer */
			*ret_r = read_more(sstream);
			if (*ret_r == 0 || *ret_r == -1)
				return TRUE;
		}

		/* we should have more now. */
		data = i_stream_get_data(sstream->cur_input, &size);
		i_assert(size > 0);

		/* change skip to 0 temporarily so i_stream_try_alloc() won't try to
		   compress the buffer. */
		size_t old_skip = stream->skip;
		stream->skip = 0;
		bool have_space = i_stream_try_alloc(stream, size, &avail_size);
		stream->skip = old_skip;
		if (!have_space)
			return FALSE;

		if (size > avail_size)
			size = avail_size;
		memcpy(stream->w_buffer + stream->pos, data, size);
		stream->pos += size;
		sstream->buffer_peak += size;
		i_stream_skip(sstream->cur_input, size);
	}

	*ret_r = size;
	i_assert(*ret_r > 0);
	return TRUE;
}

static int i_stream_seekable_write_failed(struct seekable_istream *sstream)
{
	struct istream_private *stream = &sstream->istream;
	void *data;

	i_assert(sstream->fd != -1);

	stream->max_buffer_size = (size_t)-1;
	data = i_stream_alloc(stream, sstream->write_peak);

	if (pread_full(sstream->fd, data, sstream->write_peak, 0) < 0) {
		i_error("istream-seekable: read(%s) failed: %m", sstream->temp_path);
		memarea_unref(&stream->memarea);
		return -1;
	}
	i_stream_destroy(&sstream->fd_input);
	i_close_fd(&sstream->fd);

	i_free_and_null(sstream->temp_path);
	return 0;
}

static ssize_t i_stream_seekable_read(struct istream_private *stream)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	const unsigned char *data;
	size_t size, pos;
	ssize_t ret;

	if (sstream->fd == -1) {
		if (read_from_buffer(sstream, &ret))
			return ret;

		/* copy everything to temp file and use it as the stream */
		if (copy_to_temp_file(sstream) < 0) {
			stream->max_buffer_size = (size_t)-1;
			if (!read_from_buffer(sstream, &ret))
				i_unreached();
			return ret;
		}
		i_assert(sstream->fd != -1);
	}

	stream->buffer = CONST_PTR_OFFSET(stream->buffer, stream->skip);
	stream->pos -= stream->skip;
	stream->skip = 0;

	i_assert(stream->istream.v_offset + stream->pos <= sstream->write_peak);
	if (stream->istream.v_offset + stream->pos == sstream->write_peak) {
		/* need to read more */
		if (sstream->cur_input == NULL ||
		    i_stream_get_data_size(sstream->cur_input) == 0) {
			ret = read_more(sstream);
			if (ret == -1 || ret == 0)
				return ret;
		}

		/* save to our file */
		data = i_stream_get_data(sstream->cur_input, &size);
		ret = write(sstream->fd, data, size);
		if (ret <= 0) {
			if (ret < 0 && !ENOSPACE(errno)) {
				i_error("istream-seekable: write_full(%s) failed: %m",
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
	ret = i_stream_read_memarea(sstream->fd_input);
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

static int
i_stream_seekable_stat(struct istream_private *stream, bool exact)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	const struct stat *st;
	uoff_t old_offset, len;
	ssize_t ret;

	if (sstream->size != (uoff_t)-1) {
		/* we've already reached EOF and know the size */
		stream->statbuf.st_size = sstream->size;
		return 0;
	}

	/* we want to know the full size of the file, so read until
	   we're finished */
	old_offset = stream->istream.v_offset;
	do {
		i_stream_skip(&stream->istream,
			      stream->pos - stream->skip);
	} while ((ret = i_stream_seekable_read(stream)) > 0);

	if (ret == 0) {
		i_panic("i_stream_stat() used for non-blocking "
			"seekable stream %s offset %"PRIuUOFF_T,
			i_stream_get_name(sstream->cur_input),
			sstream->cur_input->v_offset);
	}
	i_stream_skip(&stream->istream, stream->pos - stream->skip);
	len = stream->pos;
	i_stream_seek(&stream->istream, old_offset);
	unref_streams(sstream);

	if (stream->istream.stream_errno != 0)
		return -1;

	if (sstream->fd_input != NULL) {
		/* using a file backed buffer, we can use real fstat() */
		if (i_stream_stat(sstream->fd_input, exact, &st) < 0)
			return -1;
		stream->statbuf = *st;
	} else {
		/* buffer is completely in memory */
		i_assert(sstream->fd == -1);

		stream->statbuf.st_size = len;
	}
	return 0;
}

static void i_stream_seekable_seek(struct istream_private *stream,
				   uoff_t v_offset, bool mark)
{
	if (v_offset <= stream->istream.v_offset) {
		/* seeking backwards */
		stream->istream.v_offset = v_offset;
		stream->skip = stream->pos = 0;
	} else {
		/* we can't skip over data we haven't yet read and written to
		   our buffer/temp file */
		i_stream_default_seek_nonseekable(stream, v_offset, mark);
	}
}

static struct istream_snapshot *
i_stream_seekable_snapshot(struct istream_private *stream,
			   struct istream_snapshot *prev_snapshot)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;

	if (sstream->fd == -1) {
		/* still in memory */
		if (stream->memarea == NULL)
			return prev_snapshot;
		return i_stream_default_snapshot(stream, prev_snapshot);
	} else {
		/* using the fd_input stream */
		return sstream->fd_input->real_stream->
			snapshot(sstream->fd_input->real_stream, prev_snapshot);
	}
}

struct istream *
i_streams_merge(struct istream *input[], size_t max_buffer_size,
		int (*fd_callback)(const char **path_r, void *context),
		void *context) ATTR_NULL(4)
{
	struct seekable_istream *sstream;
	const unsigned char *data;
	unsigned int count;
	size_t size;
	bool blocking = TRUE;

	i_assert(max_buffer_size > 0);

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
        sstream->istream.max_buffer_size = max_buffer_size;
	sstream->fd = -1;
	sstream->size = (uoff_t)-1;

	sstream->input = i_new(struct istream *, count + 1);
	memcpy(sstream->input, input, sizeof(*input) * count);
	sstream->cur_input = sstream->input[0];

	sstream->istream.iostream.close = i_stream_seekable_close;
	sstream->istream.iostream.destroy = i_stream_seekable_destroy;
	sstream->istream.iostream.set_max_buffer_size =
		i_stream_seekable_set_max_buffer_size;

	sstream->istream.read = i_stream_seekable_read;
	sstream->istream.stat = i_stream_seekable_stat;
	sstream->istream.seek = i_stream_seekable_seek;
	sstream->istream.snapshot = i_stream_seekable_snapshot;

	sstream->istream.istream.readable_fd = FALSE;
	sstream->istream.istream.blocking = blocking;
	sstream->istream.istream.seekable = TRUE;
	(void)i_stream_create(&sstream->istream, NULL, -1, 0);

	/* initialize our buffer from first stream's pending data */
	data = i_stream_get_data(sstream->cur_input, &size);
	if (size > 0) {
		memcpy(i_stream_alloc(&sstream->istream, size), data, size);
		sstream->buffer_peak = size;
		i_stream_skip(sstream->cur_input, size);
	}
	return &sstream->istream.istream;
}

static bool inputs_are_seekable(struct istream *input[])
{
	unsigned int count;

	for (count = 0; input[count] != NULL; count++) {
		if (!input[count]->seekable)
			return FALSE;
	}
	return TRUE;
}

struct istream *
i_stream_create_seekable(struct istream *input[],
			 size_t max_buffer_size,
			 int (*fd_callback)(const char **path_r, void *context),
			 void *context)
{
	i_assert(max_buffer_size > 0);

	/* If all input streams are seekable, use concat istream instead */
	if (inputs_are_seekable(input))
		return i_stream_create_concat(input);

	return i_streams_merge(input, max_buffer_size, fd_callback, context);
}

static int seekable_fd_callback(const char **path_r, void *context)
{
	char *temp_path_prefix = context;
	string_t *path;
	int fd;

	path = t_str_new(128);
	str_append(path, temp_path_prefix);
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("istream-seekable: safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (i_unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_close_fd(&fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

struct istream *
i_stream_create_seekable_path(struct istream *input[],
			      size_t max_buffer_size,
			      const char *temp_path_prefix)
{
	struct seekable_istream *sstream;
	struct istream *stream;

	i_assert(temp_path_prefix != NULL);
	i_assert(max_buffer_size > 0);

	if (inputs_are_seekable(input))
		return i_stream_create_concat(input);

	stream = i_stream_create_seekable(input, max_buffer_size,
					  seekable_fd_callback,
					  i_strdup(temp_path_prefix));
	sstream = (struct seekable_istream *)stream->real_stream;
	sstream->free_context = TRUE;
	return stream;
}
