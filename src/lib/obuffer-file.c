/*
   obuffer-file.c : Output buffer handling for files

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
#include "network.h"
#include "sendfile-util.h"
#include "ibuffer.h"
#include "obuffer-internal.h"

#include <unistd.h>
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif

#define O_BUFFER_MIN_SIZE 4096

#define IS_BUFFER_EMPTY(fbuf) \
	(!(fbuf)->full && (fbuf)->head == (fbuf)->tail)
#define BUFFER_IS_BLOCKING(fbuf) \
	((fbuf)->timeout_msecs != 0)

#define MAX_SSIZE_T(size) \
	((size) < SSIZE_T_MAX ? (size_t)(size) : SSIZE_T_MAX)

typedef struct {
	_OBuffer obuf;

	int fd;
	int priority;
	IO io;

	unsigned char *buffer; /* ring-buffer */
	size_t buffer_size, max_buffer_size;
	size_t head, tail; /* first unsent/unused byte */

	int timeout_msecs;
	TimeoutFunc timeout_func;
	void *timeout_context;

	unsigned int full:1; /* if head == tail, is buffer empty or full? */
	unsigned int corked:1;
	unsigned int no_socket_cork:1;
	unsigned int autoclose_fd:1;
} FileOBuffer;

typedef struct {
	IOLoop ioloop;
	FileOBuffer *fbuf;
	uoff_t sent;
	int timeout;

	IBuffer *inbuf;
	struct iovec iov[3];
	unsigned int iov_len;
} IOLoopWriteContext;

static void buffer_closed(FileOBuffer *fbuf)
{
	if (fbuf->autoclose_fd && fbuf->fd != -1) {
		if (close(fbuf->fd) < 0)
			i_error("FileOBuffer.close() failed: %m");
		fbuf->fd = -1;
	}

	if (fbuf->io != NULL) {
		io_remove(fbuf->io);
		fbuf->io = NULL;
	}

	fbuf->obuf.obuffer.closed = TRUE;
}

static void _close(_IOBuffer *buf)
{
	FileOBuffer *fbuf = (FileOBuffer *) buf;

	/* flush output before really closing it */
	o_buffer_flush(&fbuf->obuf.obuffer);

	buffer_closed(fbuf);
}

static void _destroy(_IOBuffer *buf)
{
	FileOBuffer *fbuf = (FileOBuffer *) buf;

	p_free(fbuf->obuf.iobuf.pool, fbuf->buffer);
}

static void _set_max_size(_IOBuffer *buf, size_t max_size)
{
	FileOBuffer *fbuf = (FileOBuffer *) buf;

	fbuf->max_buffer_size = max_size;
}

static void _set_blocking(_IOBuffer *buf, int timeout_msecs,
			  TimeoutFunc timeout_func, void *context)
{
	FileOBuffer *fbuf = (FileOBuffer *) buf;

	fbuf->timeout_msecs = timeout_msecs;
	fbuf->timeout_func = timeout_func;
	fbuf->timeout_context = context;
}

static void _cork(_OBuffer *buf)
{
	FileOBuffer *fbuf = (FileOBuffer *) buf;

	if (!fbuf->corked) {
		if (!fbuf->no_socket_cork) {
			if (net_set_cork(fbuf->fd, TRUE) < 0)
				fbuf->no_socket_cork = TRUE;
		}
		fbuf->corked = TRUE;
	}
}

static void update_iovec(struct iovec *iov, unsigned int iov_size, size_t size)
{
	while (size > 0) {
		i_assert(iov_size > 0);

		if ((size_t)iov->iov_len <= size) {
			size -= iov->iov_len;
			iov->iov_base = NULL;
			iov->iov_len = 0;
		} else {
			iov->iov_base = (char *) iov->iov_base + size;
			iov->iov_len -= size;
			size = 0;
		}
		iov++; iov_size--;
	}
}

static void update_buffer(FileOBuffer *fbuf, size_t size)
{
	size_t used;

	if (IS_BUFFER_EMPTY(fbuf))
		return;

	if (fbuf->head < fbuf->tail) {
		/* ...HXXXT... */
		used = fbuf->tail - fbuf->head;
		fbuf->head += I_MIN(used, size);
	} else {
		/* XXXT...HXXX */
		used = fbuf->buffer_size - fbuf->head;
		if (size > used) {
			size -= used;
			if (size < fbuf->tail)
				fbuf->head = size;
			else {
				/* whole buffer is sent */
				fbuf->head = fbuf->tail = 0;
			}
		} else {
			fbuf->head += I_MIN(used, size);
		}

		fbuf->full = FALSE;
	}

	if (fbuf->head == fbuf->tail)
		fbuf->head = fbuf->tail = 0;

	if (fbuf->head == fbuf->buffer_size)
		fbuf->head = 0;
}

/* NOTE: modifies iov */
static ssize_t
o_buffer_writev(FileOBuffer *fbuf, struct iovec *iov, unsigned int iov_size)
{
	ssize_t ret;

	while (iov->iov_len == 0 && iov_size > 0) {
		iov++;
		iov_size--;
	}

	i_assert(iov_size > 0);

	ret = writev(fbuf->fd, iov, iov_size);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return 0;
		buffer_closed(fbuf);
		return -1;
	}

	update_iovec(iov, iov_size, ret);
	update_buffer(fbuf, ret);
	fbuf->obuf.obuffer.offset += ret;

	return ret;
}

static void ioloop_send(IOLoopWriteContext *ctx)
{
	if (o_buffer_writev(ctx->fbuf, ctx->iov, ctx->iov_len) < 0 ||
	    ctx->iov[ctx->iov_len-1].iov_len == 0) {
		/* error / all sent */
		io_loop_stop(ctx->ioloop);
	}
}

static void ioloop_timeout(void *context, Timeout timeout __attr_unused__)
{
	IOLoopWriteContext *ctx = context;

	ctx->timeout = TRUE;
	io_loop_stop(ctx->ioloop);
}

static int o_buffer_ioloop(FileOBuffer *fbuf, IOLoopWriteContext *ctx,
			   void (*send_func)(IOLoopWriteContext *ctx))
{
	Timeout to;
	IO io;

	/* close old IO */
	if (fbuf->io != NULL)
		io_remove(fbuf->io);

	t_push();

	/* create a new I/O loop */
	ctx->ioloop = io_loop_create(data_stack_pool);
	ctx->fbuf = fbuf;

	io = io_add(fbuf->fd, IO_WRITE, (IOFunc) send_func, ctx);
	to = fbuf->timeout_msecs <= 0 ? NULL :
		timeout_add(fbuf->timeout_msecs, ioloop_timeout, ctx);

	io_loop_run(ctx->ioloop);

	io_remove(io);

	if (to != NULL) {
		if (ctx->timeout && fbuf->timeout_func != NULL) {
			/* call user-given timeout function */
			fbuf->timeout_func(fbuf->timeout_context, to);
		}
		timeout_remove(to);
	}

	io_loop_destroy(ctx->ioloop);
	t_pop();

	return fbuf->obuf.obuffer.closed ? -1 : 1;
}

/* returns how much of vector was used */
static int o_buffer_fill_iovec(FileOBuffer *fbuf, struct iovec iov[2])
{
	if (IS_BUFFER_EMPTY(fbuf))
		return 0;

	if (fbuf->head < fbuf->tail) {
		iov[0].iov_base = fbuf->buffer + fbuf->head;
		iov[0].iov_len = fbuf->tail - fbuf->head;
		return 1;
	} else {
		iov[0].iov_base = fbuf->buffer + fbuf->head;
		iov[0].iov_len = fbuf->buffer_size - fbuf->head;
		if (fbuf->tail == 0)
			return 1;
		else {
			iov[1].iov_base = fbuf->buffer;
			iov[1].iov_len = fbuf->tail;
			return 2;
		}
	}
}

static int o_buffer_send_blocking(FileOBuffer *fbuf, const void *data,
				  size_t size)
{
	IOLoopWriteContext ctx;

	memset(&ctx, 0, sizeof(ctx));

	ctx.iov_len = o_buffer_fill_iovec(fbuf, ctx.iov);
	if (size > 0) {
		ctx.iov[ctx.iov_len].iov_base = (void *) data;
		ctx.iov[ctx.iov_len].iov_len = size;
		ctx.iov_len++;
	}

        return o_buffer_ioloop(fbuf, &ctx, ioloop_send);
}

static int buffer_flush(FileOBuffer *fbuf)
{
	struct iovec iov[2];
	int iov_len;

	if (!IS_BUFFER_EMPTY(fbuf)) {
		iov_len = o_buffer_fill_iovec(fbuf, iov);
		if (o_buffer_writev(fbuf, iov, iov_len) < 0)
			return -1;

		if (!IS_BUFFER_EMPTY(fbuf)) {
			if (o_buffer_send_blocking(fbuf, NULL, 0) < 0)
				return -1;
		}
	}

	return 1;
}

int _flush(_OBuffer *buf)
{
	FileOBuffer *fbuf = (FileOBuffer *) buf;
	int ret;

	ret = buffer_flush(fbuf);

	if (fbuf->corked) {
		/* remove cork */
		if (!fbuf->no_socket_cork) {
			if (net_set_cork(fbuf->fd, FALSE) < 0)
				i_error("net_set_cork() failed: %m");
		}
		fbuf->corked = FALSE;
	}

	return ret;
}

static size_t get_unused_space(FileOBuffer *fbuf)
{
	if (fbuf->head > fbuf->tail) {
		/* XXXT...HXXX */
		return fbuf->head - fbuf->tail;
	} else if (fbuf->head < fbuf->tail) {
		/* ...HXXXT... */
		return (fbuf->buffer_size - fbuf->tail) + fbuf->head;
	} else {
		/* either fully unused or fully used */
		return fbuf->full ? 0 : fbuf->buffer_size;
	}
}

static int _have_space(_OBuffer *buf, size_t size)
{
	FileOBuffer *fbuf = (FileOBuffer *) buf;
	size_t unused;

	if (fbuf->max_buffer_size == 0)
		return 1;

	unused = get_unused_space(fbuf);
	if (size <= unused)
		return 1;

	unused += (fbuf->max_buffer_size - fbuf->buffer_size);
	return size <= unused ? 1 : 0;
}

static int _seek(_OBuffer *buf, uoff_t offset)
{
	FileOBuffer *fbuf = (FileOBuffer *) buf;
	off_t ret;

	if (offset > OFF_T_MAX) {
		buf->obuffer.buf_errno = EINVAL;
		return -1;
	}

	ret = lseek(fbuf->fd, (off_t)offset, SEEK_SET);
	if (ret < 0) {
		buf->obuffer.buf_errno = errno;
		return -1;
	}

	if (ret != (off_t)offset) {
		buf->obuffer.buf_errno = EINVAL;
		return -1;
	}

	buf->obuffer.buf_errno = 0;
	buf->obuffer.offset = offset;
	return 1;
}

static void o_buffer_grow(FileOBuffer *fbuf, size_t bytes)
{
	size_t size, head_size;

	size = nearest_power(fbuf->buffer_size + bytes);
	if (fbuf->max_buffer_size != 0) {
		if (size > fbuf->max_buffer_size) {
			/* limit the size */
			size = fbuf->max_buffer_size;
		} else if (fbuf->corked) {
			/* use the largest possible buffer with corking */
			size = fbuf->max_buffer_size;
		}
	}

	if (size == fbuf->buffer_size)
		return;

	fbuf->buffer = p_realloc(fbuf->obuf.iobuf.pool, fbuf->buffer, size);

	if (fbuf->tail <= fbuf->head && !IS_BUFFER_EMPTY(fbuf)) {
		head_size = I_MIN(fbuf->head, size - fbuf->buffer_size);
		memcpy(fbuf->buffer + fbuf->buffer_size, fbuf->buffer,
		       head_size);

		if (head_size == fbuf->head)
			fbuf->tail = fbuf->buffer_size + head_size;
		else {
			memmove(fbuf->buffer, fbuf->buffer + head_size,
				fbuf->head - head_size);
			fbuf->tail = fbuf->head - head_size;
		}
	}

	fbuf->full = FALSE;
	fbuf->buffer_size = size;
}

static void buffer_send_io(void *context, int fd __attr_unused__,
			   IO io __attr_unused__)
{
	FileOBuffer *fbuf = context;
	struct iovec iov[2];
	int iov_len;

	iov_len = o_buffer_fill_iovec(fbuf, iov);

	if (iov_len == 0 || o_buffer_writev(fbuf, iov, iov_len) < 0 ||
	    iov[iov_len-1].iov_len == 0) {
		/* error / all sent */
		io_remove(fbuf->io);
                fbuf->io = NULL;
	}
}

static size_t o_buffer_add(FileOBuffer *fbuf, const void *data, size_t size)
{
	size_t unused, sent;
	int i;

	unused = get_unused_space(fbuf);
	if (unused < size)
		o_buffer_grow(fbuf, size-unused);

	sent = 0;
	for (i = 0; i < 2 && sent < size && !fbuf->full; i++) {
		unused = fbuf->tail >= fbuf->head ?
			fbuf->buffer_size - fbuf->tail :
			fbuf->head - fbuf->tail;

		if (unused > size-sent)
			unused = size-sent;
		memcpy(fbuf->buffer + fbuf->tail, data, unused);
		sent += unused;

		fbuf->tail += unused;
		if (fbuf->tail == fbuf->buffer_size)
			fbuf->tail = 0;

		if (fbuf->head == fbuf->tail)
			fbuf->full = TRUE;
	}

	if (sent != 0 && fbuf->io == NULL && !fbuf->corked) {
		fbuf->io = io_add_priority(fbuf->fd, fbuf->priority, IO_WRITE,
					   buffer_send_io, fbuf);
	}

	i_assert(!BUFFER_IS_BLOCKING(fbuf) || sent == size);
	return sent;
}

static ssize_t _send(_OBuffer *buf, const void *data, size_t size)
{
	FileOBuffer *fbuf = (FileOBuffer *) buf;
	struct iovec iov;
	ssize_t ret;

	i_assert(size <= SSIZE_T_MAX);

	if (buf->obuffer.closed)
		return -1;

	buf->obuffer.buf_errno = 0;

	if (IS_BUFFER_EMPTY(fbuf) &&
	    (!fbuf->corked || !_have_space(buf, size))) {
		iov.iov_base = (void *) data;
		iov.iov_len = size;
		ret = o_buffer_writev(fbuf, &iov, 1);
		if (ret < 0 || (size_t)ret == size)
			return ret;

		data = (const char *) data + ret;
		size -= ret;
	}

	if (!_have_space(buf, size) && BUFFER_IS_BLOCKING(fbuf)) {
		/* send it blocking */
		if (o_buffer_send_blocking(fbuf, data, size) < 0)
			return -1;
		return (ssize_t)size;
	} else {
		/* buffer it, at least partly */
		return (ssize_t)o_buffer_add(fbuf, data, size);
	}
}

static void ioloop_sendfile(IOLoopWriteContext *ctx)
{
	OBuffer *outbuf;
	uoff_t offset, send_size;
	ssize_t ret;
	int in_fd;

	outbuf = &ctx->fbuf->obuf.obuffer;
	in_fd = i_buffer_get_fd(ctx->inbuf);
	i_assert(in_fd != -1);

	offset = ctx->inbuf->start_offset + ctx->inbuf->v_offset;
	send_size = ctx->inbuf->v_limit - ctx->inbuf->v_offset;

	ret = safe_sendfile(ctx->fbuf->fd, in_fd, &offset,
			    MAX_SSIZE_T(send_size));
	if (ret < 0) {
		if (errno != EINTR && errno != EAGAIN) {
			outbuf->buf_errno = errno;
			buffer_closed(ctx->fbuf);
		}
		ret = 0;
	}

	i_buffer_skip(ctx->inbuf, (size_t)ret);
	outbuf->offset += ret;

	if (outbuf->closed || (size_t)ret == send_size)
		io_loop_stop(ctx->ioloop);
}

static void ioloop_copy(IOLoopWriteContext *ctx)
{
	const unsigned char *data;
	size_t size;
	int pos;

	i_assert(ctx->iov_len <= 2);

	(void)i_buffer_read_data(ctx->inbuf, &data, &size, O_BUFFER_MIN_SIZE-1);

	pos = ctx->iov_len++;
	ctx->iov[pos].iov_base = (void *) data;
	ctx->iov[pos].iov_len = size;

	if (o_buffer_writev(ctx->fbuf, ctx->iov, ctx->iov_len) < 0) {
		/* error */
		io_loop_stop(ctx->ioloop);
	}

	i_buffer_skip(ctx->inbuf, size - ctx->iov[pos].iov_len);

	do {
		ctx->iov_len--;
	} while (ctx->iov_len > 0 && ctx->iov[ctx->iov_len-1].iov_len == 0);

	if (ctx->iov_len == 0) {
		/* all sent */
		io_loop_stop(ctx->ioloop);
	}
}

static off_t o_buffer_sendfile(_OBuffer *outbuf, IBuffer *inbuf)
{
	FileOBuffer *foutbuf = (FileOBuffer *) outbuf;
        IOLoopWriteContext ctx;
	uoff_t offset, send_size;
	ssize_t s_ret;
	int in_fd;

	in_fd = i_buffer_get_fd(inbuf);
	if (in_fd == -1) {
		outbuf->obuffer.buf_errno = EINVAL;
		return -1;
	}

	/* flush out any data in buffer */
	if (buffer_flush(foutbuf) < 0)
		return -1;

	/* first try if we can do it with a single sendfile() call */
	offset = inbuf->start_offset + inbuf->v_offset;
	send_size = inbuf->v_limit - inbuf->v_offset;

	s_ret = safe_sendfile(foutbuf->fd, in_fd, &offset,
			      MAX_SSIZE_T(send_size));
	if (s_ret < 0) {
		if (errno != EINTR && errno != EAGAIN) {
			outbuf->obuffer.buf_errno = errno;
			if (errno != EINVAL) {
				/* close only if error wasn't because
				   sendfile() isn't supported */
				buffer_closed(foutbuf);
			}
			return -1;
		}
		s_ret = 0;
	}

	i_buffer_skip(inbuf, (size_t)s_ret);
	outbuf->obuffer.offset += s_ret;

	if ((uoff_t)s_ret == send_size) {
		/* yes, all sent */
		return (off_t)s_ret;
	}

	memset(&ctx, 0, sizeof(ctx));

	ctx.fbuf = foutbuf;
	ctx.inbuf = inbuf;

	if (o_buffer_ioloop(foutbuf, &ctx, ioloop_sendfile) < 0) {
		if (outbuf->obuffer.buf_errno == EINVAL) {
			/* this shouldn't happen, must be a bug. It would also
			   mess up later if we let this pass. */
			i_panic("o_buffer_sendfile() failed: %m");
		}
		return -1;
	} else {
		return (off_t)ctx.sent;
	}
}

static off_t _send_ibuffer(_OBuffer *outbuf, IBuffer *inbuf)
{
        IOLoopWriteContext ctx;
	off_t ret;

	i_assert(inbuf->v_limit <= OFF_T_MAX);
	i_assert(inbuf->v_offset <= inbuf->v_limit);

	if (inbuf->v_offset == inbuf->v_limit)
		return 0;

	ret = o_buffer_sendfile(outbuf, inbuf);
	if (ret >= 0 || outbuf->obuffer.buf_errno != EINVAL)
		return ret;

	/* sendfile() not supported, reset error */
	outbuf->obuffer.buf_errno = 0;

	/* sendfile() not supported (with this fd), fallback to
	   regular sending */

	/* create blocking send loop */
	memset(&ctx, 0, sizeof(ctx));

	ctx.fbuf = (FileOBuffer *) outbuf;
	ctx.iov_len = o_buffer_fill_iovec(ctx.fbuf, ctx.iov);
	ctx.inbuf = inbuf;

	if (o_buffer_ioloop(ctx.fbuf, &ctx, ioloop_copy) < 0)
		return -1;
	else
		return (off_t)ctx.sent;
}

OBuffer *o_buffer_create_file(int fd, Pool pool, size_t max_buffer_size,
			      int priority, int autoclose_fd)
{
	FileOBuffer *fbuf;

	fbuf = p_new(pool, FileOBuffer, 1);
	fbuf->fd = fd;
	fbuf->priority = priority;
	fbuf->max_buffer_size = max_buffer_size;
	fbuf->autoclose_fd = autoclose_fd;

	fbuf->obuf.iobuf.close = _close;
	fbuf->obuf.iobuf.destroy = _destroy;
	fbuf->obuf.iobuf.set_max_size = _set_max_size;
	fbuf->obuf.iobuf.set_blocking = _set_blocking;

	fbuf->obuf.cork = _cork;
	fbuf->obuf.flush = _flush;
	fbuf->obuf.have_space = _have_space;
	fbuf->obuf.seek = _seek;
	fbuf->obuf.send = _send;
	fbuf->obuf.send_ibuffer = _send_ibuffer;

	return _o_buffer_create(&fbuf->obuf, pool);
}
