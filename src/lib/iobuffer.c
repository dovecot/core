/*
   iobuffer.c : Input/output transmit buffer handling

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
#include "ioloop.h"
#include "iobuffer.h"
#include "mmap-util.h"
#include "sendfile-util.h"
#include "network.h"

#include <unistd.h>

#define MAX_SSIZE_T(size) ((size) < SSIZE_T_MAX ? (size_t)(size) : SSIZE_T_MAX)

typedef struct {
	IOLoop ioloop;
	IOBuffer *outbuf;

	const char *data;
	uoff_t size;
	IOBuffer *inbuf;

	int timeout;
	int last_block;
} IOBufferBlockContext;

static size_t mmap_pagesize = 0;
static size_t mmap_pagemask = 0;

IOBuffer *io_buffer_create(int fd, Pool pool, int priority,
			   size_t max_buffer_size)
{
	IOBuffer *buf;

        i_assert(fd >= 0);
        i_assert(pool != NULL);

	buf = p_new(pool, IOBuffer, 1);
	buf->fd = fd;
	buf->pool = pool;
	buf->priority = priority;
	buf->max_buffer_size = max_buffer_size;
	return buf;
}

IOBuffer *io_buffer_create_file(int fd, Pool pool, size_t max_buffer_size)
{
	IOBuffer *buf;

	buf = io_buffer_create(fd, pool, IO_PRIORITY_DEFAULT, max_buffer_size);
	buf->file = TRUE;
        return buf;
}

IOBuffer *io_buffer_create_mmap(int fd, Pool pool, size_t block_size,
				uoff_t size)
{
	IOBuffer *buf;
	off_t start_offset, stop_offset;

	/* block size must be page aligned, and at least two pages long */
	if (mmap_pagesize == 0) {
		mmap_pagesize = getpagesize();
		mmap_pagemask = mmap_pagesize-1;
	}

	if (block_size < mmap_pagesize*2)
		block_size = mmap_pagesize*2;
	else if ((block_size & mmap_pagemask) != 0) {
		block_size &= ~mmap_pagemask;
		block_size += mmap_pagesize;
	}

	buf = io_buffer_create_file(fd, pool, block_size);
	buf->mmaped = TRUE;
	buf->receive = TRUE;

	/* set offsets */
	start_offset = lseek(fd, 0, SEEK_CUR);
	stop_offset = lseek(fd, 0, SEEK_END);

	if (start_offset < 0 || stop_offset < 0) {
		i_error("io_buffer_create_mmap(): lseek() failed: %m");
		buf->start_offset = buf->size = 0;
	}

	if (start_offset > stop_offset)
		start_offset = stop_offset;

	if (size > (uoff_t) (stop_offset-start_offset)) {
		i_warning("Trying to create IOBuffer with size %"PRIuUOFF_T
			  " but we have only %"PRIuUOFF_T" bytes available "
			  "in file", size, stop_offset-start_offset);
		size = stop_offset-start_offset;
	}

	buf->start_offset = start_offset;
	buf->size = size > 0 ? size : stop_offset - start_offset;
	buf->limit = buf->size;

	buf->skip = buf->pos = buf->start_offset;
	return buf;
}

void io_buffer_destroy(IOBuffer *buf)
{
	if (buf == NULL)
		return;

        if (buf->io != NULL)
		io_remove(buf->io);
	if (buf->buffer != NULL) {
		if (!buf->mmaped)
			p_free(buf->pool, buf->buffer);
		else {
			if (munmap(buf->buffer, buf->buffer_size) < 0) {
				i_error("io_buffer_destroy(): "
					"munmap() failed: %m");
			}
		}
	}
        p_free(buf->pool, buf);
}

void io_buffer_close(IOBuffer *buf)
{
	if (buf == NULL)
		return;

        buf->closed = TRUE;
}

void io_buffer_reset(IOBuffer *buf)
{
	buf->pos = buf->skip = buf->cr_lookup_pos = 0;
	buf->last_cr = FALSE;

	if (buf->mmaped && buf->buffer != NULL) {
		if (munmap(buf->buffer, buf->buffer_size) < 0)
			i_error("io_buffer_reset(): munmap() failed: %m");
		buf->buffer = NULL;
		buf->buffer_size = 0;
	}

	buf->mmap_offset = buf->offset = 0;
}

IOBuffer *io_buffer_set_pool(IOBuffer *buf, Pool pool)
{
	IOBuffer *newbuf;

        i_assert(buf != NULL);
        i_assert(pool != NULL);

	newbuf = p_new(pool, IOBuffer, 1);
	memcpy(newbuf, buf, sizeof(IOBuffer));

	newbuf->pool = pool;

	if (!newbuf->mmaped) {
		newbuf->buffer = p_malloc(pool, buf->buffer_size);
		memcpy(newbuf->buffer, buf->buffer + buf->skip,
		       buf->buffer_size - buf->skip);

		newbuf->cr_lookup_pos -= newbuf->skip;
		newbuf->pos -= newbuf->skip;
		newbuf->skip = 0;

		p_free(buf->pool, buf->buffer);
	}

        p_free(buf->pool, buf);
        return newbuf;
}

void io_buffer_set_max_size(IOBuffer *buf, size_t max_size)
{
	i_assert(!buf->mmaped);

	buf->max_buffer_size = max_size;
}

void io_buffer_set_blocking(IOBuffer *buf, size_t max_size,
			    int timeout_msecs, TimeoutFunc timeout_func,
			    void *context)
{
	buf->timeout_msecs = timeout_msecs;
	buf->timeout_func = timeout_func;
	buf->timeout_context = context;
	buf->blocking = max_size > 0;

	if (max_size != 0)
		buf->max_buffer_size = max_size;
}

static ssize_t my_write(int fd, const void *buf, size_t size)
{
	ssize_t ret;

	i_assert(size <= SSIZE_T_MAX);

	if (size == 0)
		return 0;

	ret = write(fd, buf, size);
	if (ret < 0 && (errno == EINTR || errno == EAGAIN))
		ret = 0;

	return ret;
}

static void buf_send_real(IOBuffer *buf)
{
	int ret;

	if (!buf->file) {
		ret = net_transmit(buf->fd, buf->buffer + buf->skip,
				   buf->pos - buf->skip);
	} else {
		ret = my_write(buf->fd, buf->buffer + buf->skip,
			       buf->pos - buf->skip);
	}

	if (ret < 0) {
		buf->closed = TRUE;
		buf->buf_errno = errno;
	} else {
		buf->offset += ret;
		buf->skip += ret;
		if (buf->skip == buf->pos) {
			/* everything sent */
			buf->skip = buf->pos = 0;

			/* call flush function */
			if (buf->flush_func != NULL) {
				buf->flush_func(buf->flush_context, buf);
				buf->flush_func = NULL;

				if (buf->corked) {
					/* remove cork */
					net_set_cork(buf->fd, FALSE);
					buf->corked = FALSE;
				}
			}
		}
	}
}

static int buf_send(IOBuffer *buf)
{
	buf_send_real(buf);

	if (buf->closed || buf->pos == 0) {
		io_remove(buf->io);
                buf->io = NULL;
		return FALSE;
	}

        return TRUE;
}

static void block_loop_send(IOBufferBlockContext *ctx)
{
	size_t size;
	ssize_t ret;

	if (ctx->outbuf->skip != ctx->outbuf->pos) {
		buf_send_real(ctx->outbuf);
	} else {
		/* send the data */
		size = MAX_SSIZE_T(ctx->size);

		ret = !ctx->outbuf->file ?
			net_transmit(ctx->outbuf->fd, ctx->data, size) :
			my_write(ctx->outbuf->fd, ctx->data, size);

		if (ret < 0) {
			ctx->outbuf->closed = TRUE;
			ctx->outbuf->buf_errno = errno;
		} else {
			ctx->outbuf->offset += ret;
			ctx->data += ret;
			ctx->size -= ret;
		}
	}

	if (ctx->outbuf->closed || (ctx->size == 0 && ctx->last_block))
		io_loop_stop(ctx->ioloop);
}

/* this can be called with both io_buffer_ioloop() or
   io_buffer_read_blocking() */
static void block_loop_timeout(void *context, Timeout timeout __attr_unused__)
{
	IOBufferBlockContext *ctx = context;

	ctx->timeout = TRUE;
	io_loop_stop(ctx->ioloop);
}

static int io_buffer_ioloop(IOBuffer *buf, IOBufferBlockContext *ctx,
			    void (*send_func)(IOBufferBlockContext *ctx))
{
	Timeout to;
	int save_errno;

	/* close old IO */
	if (buf->io != NULL)
		io_remove(buf->io);

	/* create a new I/O loop */
	ctx->ioloop = io_loop_create();
	ctx->outbuf = buf;

	buf->io = io_add(buf->fd, IO_WRITE, (IOFunc) send_func, ctx);
	to = buf->timeout_msecs <= 0 ? NULL :
		timeout_add(buf->timeout_msecs, block_loop_timeout, ctx);

	io_loop_run(ctx->ioloop);
	save_errno = errno;

	if (buf->corked) {
		/* remove cork */
		net_set_cork(buf->fd, FALSE);
		buf->corked = FALSE;
	}

	if (buf->io != NULL) {
		io_remove(buf->io);
		buf->io = NULL;
	}

	if (to != NULL) {
		if (ctx->timeout && buf->timeout_func != NULL) {
			/* call user-given timeout function */
			buf->timeout_func(buf->timeout_context, to);
		}
		timeout_remove(to);
	}

	io_loop_destroy(ctx->ioloop);

	errno = save_errno;
	return ctx->size > 0 ? -1 : 1;
}

static int io_buffer_send_blocking(IOBuffer *buf, const void *data,
				   size_t size)
{
        IOBufferBlockContext ctx;

	memset(&ctx, 0, sizeof(ctx));

	ctx.data = data;
	ctx.size = size;
	ctx.last_block = TRUE;

        return io_buffer_ioloop(buf, &ctx, block_loop_send);
}

void io_buffer_cork(IOBuffer *buf)
{
	i_assert(!buf->receive);

	if (!buf->file && !buf->corked)
		net_set_cork(buf->fd, TRUE);
	buf->corked = TRUE;
}

static void buffer_alloc_more(IOBuffer *buf, size_t size)
{
	i_assert(!buf->mmaped);

	buf->buffer_size = buf->pos+size;
	buf->buffer_size =
		buf->buffer_size <= IO_BUFFER_MIN_SIZE ? IO_BUFFER_MIN_SIZE :
		nearest_power(buf->buffer_size);

	if (buf->max_buffer_size > 0 && buf->buffer_size > buf->max_buffer_size)
		buf->buffer_size = buf->max_buffer_size;

	buf->buffer = p_realloc(buf->pool, buf->buffer, buf->buffer_size);
	if (buf->buffer == NULL) {
		/* pool limit exceeded */
		buf->pos = buf->buffer_size = 0;
	}
}

static void io_buffer_compress(IOBuffer *buf)
{
	memmove(buf->buffer, buf->buffer + buf->skip,
		buf->pos - buf->skip);
	buf->pos -= buf->skip;

	if (buf->skip > buf->cr_lookup_pos)
		buf->cr_lookup_pos = 0;
	else
		buf->cr_lookup_pos -= buf->skip;

	buf->skip = 0;
}

int io_buffer_send(IOBuffer *buf, const void *data, size_t size)
{
	int i, corked, ret;

	i_assert(!buf->receive);
        i_assert(data != NULL);
	i_assert(size <= SSIZE_T_MAX);
	buf->transmit = TRUE;

	if (buf->closed)
                return -1;

	/* if we're corked, first try adding it to buffer. if it's larger
	   than the buffer, send it immediately. */
	corked = buf->corked;
	for (i = 0; i < 2; i++) {
		if (buf->pos == 0 && !corked) {
			/* buffer is empty, try to send the data immediately */
			ret = buf->file ? my_write(buf->fd, data, size) :
				net_transmit(buf->fd, data, size);
			if (ret < 0) {
				/* disconnected */
				buf->closed = TRUE;
				buf->buf_errno = errno;
				return -1;
			}

			buf->offset += ret;
			data = (const char *) data + ret;
			size -= ret;
		}

		if (size == 0) {
			/* all sent */
			return 1;
		}

		if (io_buffer_get_space(buf, size) != NULL)
			break;

		if (corked)
			corked = FALSE;
		else {
			if (buf->blocking) {
				/* if we don't have space, we block */
				return io_buffer_send_blocking(buf, data, size);
			}
			return -2;
		}
	}

	i_assert(buf->pos + size <= buf->buffer_size);

	/* add to buffer */
	memcpy(buf->buffer + buf->pos, data, size);
	buf->pos += size;

	if (buf->io == NULL) {
		buf->io = io_add_priority(buf->fd, buf->priority, IO_WRITE,
					  (IOFunc) buf_send, buf);
	}
        return 1;
}

static void block_loop_sendfile(IOBufferBlockContext *ctx)
{
	uoff_t offset;
	ssize_t ret;

	i_assert(ctx->inbuf->offset < OFF_T_MAX);

	offset = ctx->inbuf->offset;
	ret = safe_sendfile(ctx->outbuf->fd, ctx->inbuf->fd, &offset,
			    MAX_SSIZE_T(ctx->size));
	if (ret < 0) {
		if (errno != EINTR && errno != EAGAIN) {
			ctx->outbuf->buf_errno = errno;
			ctx->outbuf->closed = TRUE;
		}
		ret = 0;
	}

	io_buffer_skip(ctx->inbuf, (size_t)ret);
	ctx->outbuf->offset += ret;

	ctx->size -= ret;
	if (ctx->outbuf->closed || ctx->size == 0)
		io_loop_stop(ctx->ioloop);
}

static int io_buffer_sendfile(IOBuffer *outbuf, IOBuffer *inbuf,
			      uoff_t long_size)
{
        IOBufferBlockContext ctx;
	uoff_t offset;
	ssize_t ret;

	i_assert(inbuf->offset < OFF_T_MAX);

	io_buffer_send_flush(outbuf);

	/* first try if we can do it with a single sendfile() call */
	offset = inbuf->offset;
	ret = safe_sendfile(outbuf->fd, inbuf->fd, &offset,
			    MAX_SSIZE_T(long_size));
	if (ret < 0) {
		if (errno != EINTR && errno != EAGAIN) {
			outbuf->buf_errno = errno;
			return -1;
		}
		ret = 0;
	}

	io_buffer_skip(inbuf, (size_t)ret);
	outbuf->offset += ret;

	if ((uoff_t) ret == long_size) {
		/* yes, all sent */
		return 1;
	}

	memset(&ctx, 0, sizeof(ctx));

	ctx.inbuf = inbuf;
	ctx.size = long_size - ret;

	ret = io_buffer_ioloop(outbuf, &ctx, block_loop_sendfile);
	if (ret < 0 && outbuf->buf_errno == EINVAL) {
		/* this shouldn't happen, must be a bug. It would also
		   mess up later if we let this pass. */
		i_panic("io_buffer_sendfile() failed: %m");
	}
	return ret;
}

static void block_loop_copy(IOBufferBlockContext *ctx)
{
	unsigned char *in_data;
	size_t size, full_size, sent_size, data_size;

	if (io_buffer_read_data_blocking(ctx->inbuf, &in_data, &size, 0) < 0) {
		io_loop_stop(ctx->ioloop);
		return;
	}

	full_size = ctx->size;
	data_size = size < full_size ? size : full_size;

	/* send the data */
	ctx->size = data_size;
	ctx->data = (const char *) in_data;
	ctx->last_block = data_size == full_size;
	block_loop_send(ctx);

	/* ctx->size now contains number of bytes unsent */
	sent_size = data_size - ctx->size;
	ctx->size = full_size - sent_size;

	io_buffer_skip(ctx->inbuf, sent_size);
}

int io_buffer_send_iobuffer(IOBuffer *outbuf, IOBuffer *inbuf, uoff_t size)
{
	IOBufferBlockContext ctx;
	int ret;

	i_assert(size < OFF_T_MAX);
	i_assert(inbuf->limit > 0 || size <= inbuf->limit - inbuf->offset);

	ret = io_buffer_sendfile(outbuf, inbuf, size);
	if (ret > 0 || outbuf->buf_errno != EINVAL)
		return ret < 0 ? -1 : 1;

	/* sendfile() not supported (with this fd), fallback to
	   regular sending */

	/* create blocking send loop */
	memset(&ctx, 0, sizeof(ctx));

	ctx.inbuf = inbuf;
	ctx.size = size;

	return io_buffer_ioloop(outbuf, &ctx, block_loop_copy);
}

void io_buffer_send_flush(IOBuffer *buf)
{
	i_assert(!buf->receive);

	if (buf->closed || buf->io == NULL)
                return;

	if (buf->skip != buf->pos)
		io_buffer_send_blocking(buf, NULL, 0);
}

void io_buffer_send_flush_callback(IOBuffer *buf, IOBufferFlushFunc func,
				   void *context)
{
	i_assert(!buf->receive);

	if (buf->skip == buf->pos) {
		func(context, buf);
		return;
	}

	buf->flush_func = func;
	buf->flush_context = context;
}

static ssize_t io_buffer_set_mmaped_pos(IOBuffer *buf)
{
	buf->pos = buf->buffer_size;
	if (buf->pos - buf->skip > buf->limit - buf->offset)
		buf->pos = buf->limit - buf->offset + buf->skip;
	return buf->pos - buf->skip;
}

static ssize_t io_buffer_read_mmaped(IOBuffer *buf)
{
	size_t aligned_skip;

	if (buf->start_offset + buf->limit <=
	    (uoff_t)buf->mmap_offset + buf->pos) {
		/* end of file */
		return -1;
	}

	if (buf->pos < buf->buffer_size) {
		/* more bytes available without needing to mmap() */
		return io_buffer_set_mmaped_pos(buf);
	}

	aligned_skip = buf->skip & ~mmap_pagemask;
	if (aligned_skip == 0 && buf->buffer != NULL) {
		/* didn't skip enough bytes */
		return -2;
	}

	buf->skip -= aligned_skip;
	buf->mmap_offset += aligned_skip;

	if (buf->buffer != NULL) {
		if (munmap(buf->buffer, buf->buffer_size) < 0)
			i_error("io_buffer_read_mmaped(): munmap() failed: %m");
	}

	buf->buffer_size = buf->start_offset + buf->size - buf->mmap_offset;
	if (buf->buffer_size > buf->max_buffer_size)
		buf->buffer_size = buf->max_buffer_size;

	i_assert((uoff_t)buf->mmap_offset + buf->buffer_size <=
		 buf->start_offset + buf->size);

	buf->buffer = mmap(NULL, buf->buffer_size, PROT_READ, MAP_PRIVATE,
			   buf->fd, buf->mmap_offset);
	if (buf->buffer == MAP_FAILED) {
		buf->buf_errno = errno;
		buf->buffer = NULL;
		buf->buffer_size = 0;
		buf->skip = buf->pos;
		i_error("io_buffer_read_mmaped(): mmap() failed: %m");
		return -1;
	}

	(void)madvise(buf->buffer, buf->buffer_size, MADV_SEQUENTIAL);

	return io_buffer_set_mmaped_pos(buf);
}

void io_buffer_set_read_limit(IOBuffer *inbuf, uoff_t offset)
{
	i_assert(offset <= inbuf->size);

	if (offset == 0)
		inbuf->limit = inbuf->size;
	else {
		i_assert(offset >= inbuf->offset);

		inbuf->limit = offset;
		if (inbuf->offset + (inbuf->pos - inbuf->skip) > offset)
			inbuf->pos = offset - inbuf->offset + inbuf->skip;
	}
}

ssize_t io_buffer_read(IOBuffer *buf)
{
	size_t size;
	ssize_t ret;

	i_assert(!buf->transmit);
	buf->receive = TRUE;

	if (buf->closed)
		return -1;

	if (buf->mmaped)
		return io_buffer_read_mmaped(buf);

	if (buf->pos == buf->buffer_size) {
		if (buf->skip > 0) {
			/* remove the unused bytes from beginning of buffer */
                        io_buffer_compress(buf);
		} else if (buf->max_buffer_size == 0 ||
			   buf->buffer_size < buf->max_buffer_size) {
			/* buffer is full - grow it */
			buffer_alloc_more(buf, IO_BUFFER_MIN_SIZE);
		}

		if (buf->pos == buf->buffer_size)
                        return -2; /* buffer full */
	}

	size = buf->buffer_size - buf->pos;
	if (buf->limit > 0) {
		i_assert(buf->limit >= buf->offset);
		if (size >= buf->limit - buf->offset) {
			size = buf->limit - buf->offset;
			if (size == 0)
				return -1;
		}
	}

        /* fill the buffer */
	if (!buf->file) {
		ret = net_receive(buf->fd, buf->buffer + buf->pos, size);
	} else {
		ret = read(buf->fd, buf->buffer + buf->pos, size);
		if (ret == 0)
			ret = -1; /* EOF */
		else if (ret < 0 && (errno == EINTR || errno == EAGAIN))
                        ret = 0;
	}

	if (ret < 0) {
		/* disconnected */
		buf->buf_errno = errno;
                return -1;
	}

	buf->pos += ret;
        return ret;
}

static void io_read_data(void *context, int fd __attr_unused__,
			 IO io __attr_unused__)
{
	IOBufferBlockContext *ctx = context;

	if (io_buffer_read(ctx->inbuf) != 0) {
		/* got data / error */
		io_loop_stop(ctx->ioloop);
	}
}

ssize_t io_buffer_read_blocking(IOBuffer *buf)
{
        IOBufferBlockContext ctx;
	Timeout to;
	ssize_t ret;

	/* first check if we can get some data */
	ret = io_buffer_read(buf);
	if (ret != 0)
		return ret;

	/* blocking now */

	/* create a new I/O loop */
	memset(&ctx, 0, sizeof(ctx));
	ctx.ioloop = io_loop_create();
	ctx.inbuf = buf;

	buf->io = io_add(buf->fd, IO_READ, io_read_data, &ctx);
	to = buf->timeout_msecs <= 0 ? NULL :
		timeout_add(buf->timeout_msecs, block_loop_timeout, &ctx);

	io_loop_run(ctx.ioloop);

	if (buf->io != NULL) {
		io_remove(buf->io);
		buf->io = NULL;
	}

	if (to != NULL) {
		if (ctx.timeout && buf->timeout_func != NULL) {
			/* call user-given timeout function */
			buf->timeout_func(buf->timeout_context, to);
		}
		timeout_remove(to);
	}

	io_loop_destroy(ctx.ioloop);

	return buf->pos > buf->skip ?
		(ssize_t) (buf->pos-buf->skip) : -1;
}

void io_buffer_skip(IOBuffer *buf, uoff_t count)
{
	uoff_t old_limit;
	ssize_t ret;

	buf->offset += count;

	if (count <= buf->pos - buf->skip) {
		buf->skip += count;
		return;
	}

	if (buf->mmaped) {
		/* these point outside mmap now, next io_buffer_read_mmaped()
		   will fix them */
		buf->skip += count;
		buf->pos = buf->skip;
	} else {
		if (buf->buffer_size == 0)
			buffer_alloc_more(buf, IO_BUFFER_MIN_SIZE);

		count -= buf->skip;

		old_limit = buf->limit;
		io_buffer_set_read_limit(buf, buf->offset + count);

		while ((ret = io_buffer_read_blocking(buf)) > 0)
			io_buffer_skip(buf, ret);

		io_buffer_set_read_limit(buf, old_limit);
	}
}

int io_buffer_seek(IOBuffer *buf, uoff_t offset)
{
	uoff_t real_offset;

	real_offset = buf->start_offset + offset;
	if (real_offset > OFF_T_MAX) {
		errno = EINVAL;
		return FALSE;
	}

	if (buf->mmaped) {
		/* first reset everything */
		io_buffer_reset(buf);

		/* then set the wanted position, next read will
		   pick up from there */
		buf->pos = buf->skip = real_offset;
	} else {
		if (lseek(buf->fd, (off_t)real_offset, SEEK_SET) !=
		    (off_t)real_offset)
			return FALSE;
	}

	buf->offset = offset;
	return TRUE;
}

/* skip the first LF, if it exists */
static void io_buffer_skip_lf(IOBuffer *buf)
{
	if (!buf->last_cr || buf->skip >= buf->pos)
		return;

	if (buf->buffer[buf->skip] == 10) {
		if (buf->skip == buf->cr_lookup_pos)
			buf->cr_lookup_pos++;
		buf->skip++;
		buf->offset++;
	}
	buf->last_cr = FALSE;
}

char *io_buffer_next_line(IOBuffer *buf)
{
	/* FIXME: buf->offset isn't updated right.. (skip_lf thing?) */
	unsigned char *ret_buf;
        size_t i;

        i_assert(buf != NULL);

	io_buffer_skip_lf(buf);
	if (buf->skip >= buf->pos)
		return NULL;

	ret_buf = NULL;
	for (i = buf->cr_lookup_pos; i < buf->pos; i++) {
		if (buf->buffer[i] == 13 || buf->buffer[i] == 10) {
			/* got it */
                        buf->last_cr = buf->buffer[i] == 13;
			buf->buffer[i] = '\0';
			ret_buf = buf->buffer + buf->skip;

			i++;
			buf->offset += i - buf->skip;
			buf->skip = i;
                        break;
		}
	}

	buf->cr_lookup_pos = i;
        return ret_buf;
}

unsigned char *io_buffer_get_data(IOBuffer *buf, size_t *size)
{
	io_buffer_skip_lf(buf);

	if (buf->skip >= buf->pos) {
		*size = 0;
		return NULL;
	}

        *size = buf->pos - buf->skip;
        return buf->buffer + buf->skip;
}

int io_buffer_read_data_blocking(IOBuffer *buf, unsigned char **data,
				 size_t *size, size_t threshold)
{
	ssize_t ret;

	while (buf->pos - buf->skip <= threshold) {
		/* we need more data */
		ret = io_buffer_read_blocking(buf);
		if (ret < 0) {
			if (ret == -2)
				return -2;
			else
				break;
		}
	}

	*data = io_buffer_get_data(buf, size);
	return *size > threshold ? 1 : *size > 0 ? 0 : -1;
}

unsigned char *io_buffer_get_space(IOBuffer *buf, size_t size)
{
	i_assert(size > 0);
	i_assert(size <= SSIZE_T_MAX);
	i_assert(!buf->receive);
	buf->transmit = TRUE;

	/* make sure we have enough space in buffer */
	if (buf->buffer_size - buf->pos < size && buf->skip > 0) {
		/* remove the unused bytes from beginning of buffer */
		io_buffer_compress(buf);
	}

	if (buf->buffer_size - buf->pos < size &&
	    (buf->max_buffer_size == 0 ||
	     size <= buf->max_buffer_size - buf->pos)) {
		/* allocate more space */
                buffer_alloc_more(buf, size);
	}

	if (buf->buffer_size - buf->pos < size)
                return NULL;

        return buf->buffer + buf->pos;
}

int io_buffer_send_buffer(IOBuffer *buf, size_t size)
{
	ssize_t ret;

	i_assert(size <= SSIZE_T_MAX);
	i_assert(!buf->receive);

	if (buf->pos == 0 && !buf->corked) {
		/* buffer is empty, try to send the data immediately */
		ret = buf->file ? my_write(buf->fd, buf->buffer, size) :
			net_transmit(buf->fd, buf->buffer, size);
		if (ret < 0) {
			/* disconnected */
			buf->closed = TRUE;
			buf->buf_errno = errno;
			return -1;
		}

		buf->offset += ret;
		if ((size_t)ret == size) {
                        /* all sent */
			return 1;
		}

		buf->skip += ret;
	}

	buf->pos += size;

	if (buf->io == NULL) {
		buf->io = io_add_priority(buf->fd, buf->priority, IO_WRITE,
					  (IOFunc) buf_send, buf);
	}

        return 1;
}

int io_buffer_set_data(IOBuffer *buf, const void *data, size_t size)
{
	i_assert(!buf->mmaped);

	io_buffer_reset(buf);

	if (buf->buffer_size < size) {
		buffer_alloc_more(buf, size);
		if (buf->buffer_size < size)
                        return -2;
	}

        buf->offset += size;
        buf->offset -= buf->pos - buf->skip;

	memcpy(buf->buffer, data, size);
	buf->pos = size;
	buf->skip = 0;
	return 1;
}

int io_buffer_is_empty(IOBuffer *buf)
{
        return buf->skip >= buf->pos;
}
