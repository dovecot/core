/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "randgen.h"
#include "write-full.h"
#include "istream-internal.h"
#include "istream-seekable.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define BUF_INITIAL_SIZE (1024*32)

struct seekable_istream {
	struct _istream istream;
	pool_t pool;

	size_t max_buffer_size;
	char *temp_prefix;
	uoff_t write_peak;

	buffer_t *buffer;
	struct istream **input, *cur_input;
	struct istream *fd_input;
	unsigned int cur_idx;
	int fd;
};

static void _close(struct _iostream *stream __attr_unused__)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	unsigned int i;

	sstream->fd = -1;
	if (sstream->fd_input != NULL)
		i_stream_close(sstream->fd_input);
	for (i = 0; sstream->input[i] != NULL; i++)
		i_stream_close(sstream->input[i]);
}

static void _destroy(struct _iostream *stream)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	unsigned int i;

	if (sstream->buffer != NULL)
		buffer_free(sstream->buffer);
	if (sstream->fd_input != NULL)
		i_stream_unref(&sstream->fd_input);
	for (i = 0; sstream->input[i] != NULL; i++)
		i_stream_unref(&sstream->input[i]);

	p_free(sstream->pool, sstream->temp_prefix);
	pool_unref(sstream->pool);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	unsigned int i;

	sstream->max_buffer_size = max_size;
	if (sstream->fd_input != NULL)
		i_stream_set_max_buffer_size(sstream->fd_input, max_size);
	for (i = 0; sstream->input[i] != NULL; i++)
		i_stream_set_max_buffer_size(sstream->input[i], max_size);
}

static int copy_to_temp_file(struct seekable_istream *sstream)
{
	unsigned char randbuf[8];
	const char *path;
	struct stat st;
	int fd;

	/* create a temporary file */
	for (;;) {
		random_fill_weak(randbuf, sizeof(randbuf));
		path = t_strconcat(sstream->temp_prefix, ".",
				   dec2str(time(NULL)), ".",
				   dec2str(getpid()), ".",
				   binary_to_hex(randbuf, sizeof(randbuf)),
				   NULL);
		if (stat(path, &st) == 0)
			continue;

		if (errno != ENOENT) {
			i_error("stat(%s) failed: %m", path);
			return -1;
		}

		fd = open(path, O_RDWR | O_EXCL | O_CREAT, 0600);
		if (fd != -1)
			break;

		if (errno != EEXIST) {
			i_error("open(%s) failed: %m", path);
			return -1;
		}
	}

	/* we just want the fd, unlink it */
	if (unlink(path) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", path);
		(void)close(fd);
		return -1;
	}

	/* copy our currently read buffer to it */
	if (write_full(fd, sstream->buffer->data, sstream->buffer->used) < 0) {
		i_error("write_full(%s) failed: %m", path);
		(void)close(fd);
		return -1;
	}
	sstream->write_peak = sstream->buffer->used;

	buffer_free(sstream->buffer);
	sstream->buffer = NULL;

	sstream->fd = fd;
	sstream->fd_input =
		i_stream_create_file(fd, sstream->pool,
				     sstream->max_buffer_size, TRUE);
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
			/* error */
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

static bool read_from_buffer(struct seekable_istream *sstream, ssize_t *ret)
{
	struct _istream *stream = &sstream->istream;
	const unsigned char *data;
	size_t size, pos, offset;

	if (stream->istream.v_offset +
	    (stream->pos - stream->skip) >= sstream->buffer->used) {
		/* need to read more */
		if (sstream->buffer->used >= sstream->max_buffer_size)
			return FALSE;

		/* read more to buffer */
		*ret = read_more(sstream);
		if (*ret <= 0)
			return TRUE;

		/* we should have more now. */
		data = i_stream_get_data(sstream->cur_input, &size);
		buffer_append(sstream->buffer, data, size);
		i_stream_skip(sstream->cur_input, size);
	}

	offset = stream->istream.v_offset;
	stream->buffer = CONST_PTR_OFFSET(sstream->buffer->data, offset);
	pos = sstream->buffer->used - offset;

	*ret = pos - stream->pos;
	stream->pos = pos;
	return TRUE;
}

static ssize_t _read(struct _istream *stream)
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
			i_stream_close(&stream->istream);
			return -1;
		}
		i_assert(sstream->buffer == NULL);
	}

	while (stream->istream.v_offset + stream->pos >= sstream->write_peak) {
		/* need to read more */
		ret = read_more(sstream);
		if (ret <= 0)
			return ret;

		/* save to our file */
		data = i_stream_get_data(sstream->cur_input, &size);
		if (write_full(sstream->fd, data, size) < 0) {
			i_error("write_full(%s...) failed: %m",
				sstream->temp_prefix);
			i_stream_close(&stream->istream);
			return -1;
		}
		i_stream_sync(sstream->fd_input);
		i_stream_skip(sstream->cur_input, size);
		sstream->write_peak += size;
	}

	i_stream_seek(sstream->fd_input, stream->istream.v_offset);
	ret = i_stream_read(sstream->fd_input);
	if (ret <= 0) {
		stream->istream.eof = sstream->fd_input->eof;
		stream->istream.stream_errno =
			sstream->fd_input->stream_errno;
	}

	stream->buffer = i_stream_get_data(sstream->fd_input, &pos);
	stream->pos -= stream->skip;
	stream->skip = 0;

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) : ret;
	stream->pos = pos;
	return ret;
}

static void _seek(struct _istream *stream, uoff_t v_offset,
		  bool mark __attr_unused__)
{
	stream->istream.stream_errno = 0;
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
}

static const struct stat *_stat(struct _istream *stream, bool exact)
{
	struct seekable_istream *sstream = (struct seekable_istream *)stream;
	uoff_t old_offset;
	ssize_t ret;

	if (sstream->buffer != NULL) {
		/* we want to know the full size of the file, so read until
		   we're finished */
		old_offset = stream->istream.v_offset;
		do {
			i_stream_skip(&stream->istream, stream->skip);
		} while ((ret = _read(stream)) > 0);

		if (ret == 0) {
			i_panic("i_stream_stat() used for non-blocking "
				"seekable stream");
		}
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
i_stream_create_seekable(struct istream *input[], pool_t pool,
			 size_t max_buffer_size, const char *temp_prefix)
{
	struct seekable_istream *sstream;
	const unsigned char *data;
	unsigned int count;
	size_t size;

	for (count = 0; input[count] != NULL; count++)
		i_stream_ref(input[count]);
	i_assert(count != 0);

	pool_ref(pool);
	sstream = p_new(pool, struct seekable_istream, 1);
	sstream->pool = pool;
	sstream->temp_prefix = p_strdup(pool, temp_prefix);
	sstream->buffer = buffer_create_dynamic(pool, BUF_INITIAL_SIZE);
        sstream->max_buffer_size = max_buffer_size;

	sstream->input = p_new(pool, struct istream *, count + 1);
	memcpy(sstream->input, input, sizeof(*input) * count);
	sstream->cur_input = sstream->input[0];

	/* initialize our buffer from first stream's pending data */
	data = i_stream_get_data(sstream->cur_input, &size);
	buffer_append(sstream->buffer, data, size);
	i_stream_skip(sstream->cur_input, size);

	sstream->istream.iostream.close = _close;
	sstream->istream.iostream.destroy = _destroy;
	sstream->istream.iostream.set_max_buffer_size = _set_max_buffer_size;

	sstream->istream.read = _read;
	sstream->istream.seek = _seek;
	sstream->istream.stat = _stat;

	return _i_stream_create(&sstream->istream, pool, -1, 0);
}
