/*
   ibuffer-file.c : Input buffer handling for files

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

#include "lib.h"
#include "ibuffer-internal.h"

#include <unistd.h>

#define I_BUFFER_MIN_SIZE 1024

typedef struct {
	_IBuffer ibuf;

	size_t max_buffer_size;
	uoff_t skip_left;

	int timeout_msecs;
	TimeoutFunc timeout_func;
	void *timeout_context;

	unsigned int autoclose_fd:1;
} FileIBuffer;

typedef struct {
	IOLoop ioloop;
	IBuffer *buf;
	int timeout;
} IOLoopReadContext;

static void _close(_IOBuffer *buf)
{
	FileIBuffer *fbuf = (FileIBuffer *) buf;
	_IBuffer *_buf = (_IBuffer *) buf;

	if (fbuf->autoclose_fd && _buf->fd != -1) {
		if (close(_buf->fd) < 0)
			i_error("FileIBuffer.close() failed: %m");
		_buf->fd = -1;
	}
}

static void _destroy(_IOBuffer *buf)
{
	_IBuffer *_buf = (_IBuffer *) buf;

	p_free(_buf->iobuf.pool, _buf->w_buffer);
}

static void _set_max_size(_IOBuffer *buf, size_t max_size)
{
	FileIBuffer *fbuf = (FileIBuffer *) buf;

	fbuf->max_buffer_size = max_size;
}

static void _set_blocking(_IOBuffer *buf, int timeout_msecs,
			  TimeoutFunc timeout_func, void *context)
{
	FileIBuffer *fbuf = (FileIBuffer *) buf;

	fbuf->timeout_msecs = timeout_msecs;
	fbuf->timeout_func = timeout_func;
	fbuf->timeout_context = context;
}

static void i_buffer_grow(_IBuffer *buf, size_t bytes)
{
	FileIBuffer *fbuf = (FileIBuffer *) buf;

	buf->buffer_size = buf->pos + bytes;
	buf->buffer_size =
		buf->buffer_size <= I_BUFFER_MIN_SIZE ? I_BUFFER_MIN_SIZE :
		nearest_power(buf->buffer_size);

	if (fbuf->max_buffer_size > 0 &&
	    buf->buffer_size > fbuf->max_buffer_size)
		buf->buffer_size = fbuf->max_buffer_size;

	buf->buffer = buf->w_buffer =
		p_realloc(buf->iobuf.pool, buf->w_buffer, buf->buffer_size);
}

static void i_buffer_compress(_IBuffer *buf)
{
	memmove(buf->w_buffer, buf->w_buffer + buf->skip,
		buf->pos - buf->skip);
	buf->pos -= buf->skip;

	if (buf->skip > buf->cr_lookup_pos)
		buf->cr_lookup_pos = 0;
	else
		buf->cr_lookup_pos -= buf->skip;

	buf->skip = 0;
}

static void ioloop_read(void *context, int fd __attr_unused__,
			IO io __attr_unused__)
{
	IOLoopReadContext *ctx = context;

	if (i_buffer_read(ctx->buf) != 0) {
		/* got data / error */
		io_loop_stop(ctx->ioloop);
	}
}

static void ioloop_timeout(void *context, Timeout timeout __attr_unused__)
{
	IOLoopReadContext *ctx = context;

	ctx->timeout = TRUE;
	io_loop_stop(ctx->ioloop);
}

static ssize_t i_buffer_read_blocking(_IBuffer *buf)
{
	FileIBuffer *fbuf = (FileIBuffer *) buf;
        IOLoopReadContext ctx;
	Timeout to;
	IO io;

	t_push();

	/* create a new I/O loop */
	memset(&ctx, 0, sizeof(ctx));
	ctx.ioloop = io_loop_create(data_stack_pool);
	ctx.buf = &buf->ibuffer;

	io = io_add(buf->fd, IO_READ, ioloop_read, &ctx);
	to = fbuf->timeout_msecs <= 0 ? NULL :
		timeout_add(fbuf->timeout_msecs, ioloop_timeout, &ctx);

	io_loop_run(ctx.ioloop);

	io_remove(io);
	if (to != NULL) {
		if (ctx.timeout && fbuf->timeout_func != NULL) {
			/* call user-given timeout function */
			fbuf->timeout_func(fbuf->timeout_context, to);
		}
		timeout_remove(to);
	}

	io_loop_destroy(ctx.ioloop);
	t_pop();

	return buf->pos > buf->skip ? (ssize_t) (buf->pos-buf->skip) : -1;
}

static ssize_t _read(_IBuffer *buf)
{
	FileIBuffer *fbuf = (FileIBuffer *) buf;
	size_t size;
	ssize_t ret;

	if (buf->ibuffer.closed)
		return -1;

	buf->ibuffer.buf_errno = 0;

	if (buf->pos == buf->buffer_size) {
		if (buf->skip > 0) {
			/* remove the unused bytes from beginning of buffer */
                        i_buffer_compress(buf);
		} else if (fbuf->max_buffer_size == 0 ||
			   buf->buffer_size < fbuf->max_buffer_size) {
			/* buffer is full - grow it */
			i_buffer_grow(buf, I_BUFFER_MIN_SIZE);
		}

		if (buf->pos == buf->buffer_size)
                        return -2; /* buffer full */
	}

	size = buf->buffer_size - buf->pos;
	if (buf->ibuffer.v_limit > 0) {
		i_assert(buf->ibuffer.v_limit >= buf->ibuffer.v_offset);
		if (size >= buf->ibuffer.v_limit - buf->ibuffer.v_offset) {
			size = buf->ibuffer.v_limit - buf->ibuffer.v_offset;
			if (size == 0) {
				/* virtual limit reached == EOF */
				return -1;
			}
		}
	}

	ret = read(buf->fd, buf->w_buffer + buf->pos, size);
	if (ret == 0) {
		/* EOF */
		return -1;
	}

	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN)
			ret = 0;
		else {
			buf->ibuffer.buf_errno = errno;
			return -1;
		}
	}
	buf->pos += ret;

	do {
		if (ret == 0 && fbuf->timeout_msecs > 0) {
			/* blocking read */
			ret = i_buffer_read_blocking(buf);
		}

		if (ret > 0 && fbuf->skip_left > 0) {
			if (fbuf->skip_left > (uoff_t)ret) {
				buf->skip += ret;
				fbuf->skip_left -= ret;
				ret = 0;
			} else {
				ret -= fbuf->skip_left;
				buf->skip -= fbuf->skip_left;
				fbuf->skip_left = 0;
			}
		}
	} while (ret == 0 && fbuf->timeout_msecs != 0);

	return ret;
}

static void _skip(_IBuffer *buf, uoff_t count)
{
	FileIBuffer *fbuf = (FileIBuffer *) buf;
	uoff_t old_limit;
	ssize_t ret;
	off_t skipped;

	if (buf->buffer_size == 0)
		i_buffer_grow(buf, I_BUFFER_MIN_SIZE);

	skipped = 0;
	old_limit = buf->ibuffer.v_limit;
	i_buffer_set_read_limit(&buf->ibuffer, buf->ibuffer.v_offset + count);

	while (count > 0 && (ret = i_buffer_read(&buf->ibuffer)) > 0) {
		if ((size_t)ret > count)
			ret = count;

		count -= ret;
		buf->skip += ret;
		buf->ibuffer.v_offset += ret;
	}

	i_buffer_set_read_limit(&buf->ibuffer, old_limit);

	fbuf->skip_left = count;
	buf->ibuffer.v_offset += count;
}

static int _seek(_IBuffer *buf, uoff_t v_offset)
{
	uoff_t real_offset;
	off_t ret;

	real_offset = buf->ibuffer.start_offset + v_offset;
	if (real_offset > OFF_T_MAX) {
		buf->ibuffer.buf_errno = EINVAL;
		return -1;
	}

	ret = lseek(buf->fd, (off_t)real_offset, SEEK_SET);
	if (ret < 0) {
		buf->ibuffer.buf_errno = errno;
		return -1;
	}

	if (ret != (off_t)real_offset) {
		buf->ibuffer.buf_errno = EINVAL;
		return -1;
	}

	buf->ibuffer.buf_errno = 0;
	buf->ibuffer.v_offset = v_offset;
	return 1;
}

IBuffer *i_buffer_create_file(int fd, Pool pool, size_t max_buffer_size,
			      int autoclose_fd)
{
	FileIBuffer *mbuf;

	mbuf = p_new(pool, FileIBuffer, 1);
	mbuf->max_buffer_size = max_buffer_size;
	mbuf->autoclose_fd = autoclose_fd;

	mbuf->ibuf.iobuf.close = _close;
	mbuf->ibuf.iobuf.destroy = _destroy;
	mbuf->ibuf.iobuf.set_max_size = _set_max_size;
	mbuf->ibuf.iobuf.set_blocking = _set_blocking;

	mbuf->ibuf.read = _read;
	mbuf->ibuf.skip_count = _skip;
	mbuf->ibuf.seek = _seek;

	return _i_buffer_create(&mbuf->ibuf, pool, fd, 0, 0);
}
