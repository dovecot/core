/*
   istream-file.c : Input stream handling for files

    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/* @UNSAFE: whole file */

#include "lib.h"
#include "alarm-hup.h"
#include "istream-internal.h"
#include "network.h"

#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define I_STREAM_MIN_SIZE 4096

#define STREAM_IS_BLOCKING(fstream) \
	((fstream)->timeout_msecs != 0)

struct file_istream {
	struct _istream istream;

	size_t max_buffer_size;
	uoff_t skip_left;

	int timeout_msecs;
	void (*timeout_cb)(void *);
	void *timeout_context;

	unsigned int file:1;
	unsigned int autoclose_fd:1;
};

static void _close(struct _iostream *stream)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	struct _istream *_stream = (struct _istream *) stream;

	if (fstream->autoclose_fd && _stream->fd != -1) {
		if (close(_stream->fd) < 0)
			i_error("file_istream.close() failed: %m");
		_stream->fd = -1;
	}
}

static void _destroy(struct _iostream *stream)
{
	struct _istream *_stream = (struct _istream *) stream;

	p_free(_stream->iostream.pool, _stream->w_buffer);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct file_istream *fstream = (struct file_istream *) stream;

	fstream->max_buffer_size = max_size;
}

static void _set_blocking(struct _iostream *stream, int timeout_msecs,
			  void (*timeout_cb)(void *), void *context)
{
	struct file_istream *fstream = (struct file_istream *) stream;

	fstream->timeout_msecs = timeout_msecs;
	fstream->timeout_cb = timeout_cb;
	fstream->timeout_context = context;

	net_set_nonblock(fstream->istream.fd, timeout_msecs == 0);

	if (timeout_msecs != 0)
		alarm_hup_init();
}

static void i_stream_grow_buffer(struct _istream *stream, size_t bytes)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	size_t old_size;

	old_size = stream->buffer_size;

	stream->buffer_size = stream->pos + bytes;
	if (stream->buffer_size <= I_STREAM_MIN_SIZE)
		stream->buffer_size = I_STREAM_MIN_SIZE;
	else
		stream->buffer_size = nearest_power(stream->buffer_size);

	if (fstream->max_buffer_size > 0 &&
	    stream->buffer_size > fstream->max_buffer_size)
		stream->buffer_size = fstream->max_buffer_size;

	stream->buffer = stream->w_buffer =
		p_realloc(stream->iostream.pool, stream->w_buffer,
			  old_size, stream->buffer_size);
}

static void i_stream_compress(struct _istream *stream)
{
	memmove(stream->w_buffer, stream->w_buffer + stream->skip,
		stream->pos - stream->skip);
	stream->pos -= stream->skip;

	stream->skip = 0;
}

static ssize_t _read(struct _istream *stream)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	time_t timeout_time;
	uoff_t read_limit;
	size_t size;
	ssize_t ret;

	if (stream->istream.closed)
		return -1;

	if (fstream->skip_left > 0) {
		i_assert(stream->skip == stream->pos);

		if (fstream->file) {
			/* we're a file, so we can lseek() */
			i_stream_seek(&stream->istream,
				      stream->istream.v_offset);
			if (stream->istream.closed)
				return -1;
		}
	}

	stream->istream.stream_errno = 0;

	if (stream->pos == stream->buffer_size) {
		if (stream->skip > 0) {
			/* remove the unused bytes from beginning of buffer */
                        i_stream_compress(stream);
		} else if (fstream->max_buffer_size == 0 ||
			   stream->buffer_size < fstream->max_buffer_size) {
			/* buffer is full - grow it */
			i_stream_grow_buffer(stream, I_STREAM_MIN_SIZE);
		}

		if (stream->pos == stream->buffer_size)
			return -2; /* buffer full */
	}

	size = stream->buffer_size - stream->pos;
	if (stream->istream.v_limit > 0) {
		i_assert(stream->istream.v_limit >= stream->istream.v_offset);

		read_limit = stream->istream.v_limit -
			stream->istream.v_offset + fstream->skip_left;
		if (read_limit <= stream->pos - stream->skip) {
			/* virtual limit reached == EOF */
			return -1;
		}

		read_limit -= stream->pos - stream->skip;
		if (size > read_limit)
			size = read_limit;
	}

	timeout_time = GET_TIMEOUT_TIME(fstream);

	ret = -1;
	do {
		if (ret == 0 && timeout_time > 0 && time(NULL) > timeout_time) {
			/* timeouted */
			if (fstream->timeout_cb != NULL)
				fstream->timeout_cb(fstream->timeout_context);
			stream->istream.stream_errno = EAGAIN;
			return -1;
		}

		ret = read(stream->fd, stream->w_buffer + stream->pos, size);
		if (ret == 0) {
			/* EOF */
			stream->istream.stream_errno = 0;
			return -1;
		}

		if (ret < 0) {
			if (errno == ECONNRESET || errno == ETIMEDOUT) {
				/* treat as disconnection */
				stream->istream.stream_errno = 0;
				return -1;
			}

			if (errno == EINTR || errno == EAGAIN)
				ret = 0;
			else {
				stream->istream.stream_errno = errno;
				return -1;
			}
		}

		if (ret > 0 && fstream->skip_left > 0) {
			if (fstream->skip_left >= (size_t)ret) {
				fstream->skip_left -= ret;
				ret = 0;
			} else {
				ret -= fstream->skip_left;
				stream->pos += fstream->skip_left;
				stream->skip += fstream->skip_left;
				fstream->skip_left = 0;
			}
		}
	} while (ret == 0 && STREAM_IS_BLOCKING(fstream));

	stream->pos += ret;
	return ret;
}

static void _skip(struct _istream *stream, uoff_t count)
{
	struct file_istream *fstream = (struct file_istream *) stream;

	fstream->skip_left += count - (stream->pos - stream->skip);
	stream->skip = stream->pos = 0;
	stream->istream.v_offset += count;
}

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	uoff_t real_offset;
	off_t ret;

	real_offset = stream->istream.start_offset + v_offset;
	if (real_offset > OFF_T_MAX) {
		stream->istream.stream_errno = EOVERFLOW;
		ret = -1;
	} else {
		ret = lseek(stream->fd, (off_t)real_offset, SEEK_SET);
		if (ret < 0)
			stream->istream.stream_errno = errno;
		else if (ret != (off_t)real_offset) {
			stream->istream.stream_errno = EINVAL;
			ret = -1;
		} else {
			stream->skip = stream->pos = 0;
			fstream->skip_left = 0;
		}
	}

	if (ret < 0)
                i_stream_close(&stream->istream);
	else {
		stream->istream.stream_errno = 0;
		stream->istream.v_offset = v_offset;
	}
}

struct istream *i_stream_create_file(int fd, pool_t pool,
				     size_t max_buffer_size, int autoclose_fd)
{
	struct file_istream *fstream;
	struct stat st;

	fstream = p_new(pool, struct file_istream, 1);
	fstream->max_buffer_size = max_buffer_size;
	fstream->autoclose_fd = autoclose_fd;

	fstream->istream.iostream.close = _close;
	fstream->istream.iostream.destroy = _destroy;
	fstream->istream.iostream.set_max_buffer_size = _set_max_buffer_size;
	fstream->istream.iostream.set_blocking = _set_blocking;

	fstream->istream.read = _read;
	fstream->istream.skip_count = _skip;
	fstream->istream.seek = _seek;

	/* get size of fd if it's a file */
	if (fstat(fd, &st) < 0)
		st.st_size = 0;
	else if (S_ISREG(st.st_mode))
		fstream->file = TRUE;

	return _i_stream_create(&fstream->istream, pool, fd, 0,
				(uoff_t)st.st_size);
}
