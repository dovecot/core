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
#include "network.h"

#include <unistd.h>

#ifdef HAVE_SYS_SENDFILE_H
#  include <sys/sendfile.h>
#endif

IOBuffer *io_buffer_create(int fd, Pool pool, int priority,
			   unsigned int max_size)
{
	IOBuffer *buf;

        i_assert(fd >= 0);
        i_assert(pool != NULL);

	buf = p_new(pool, IOBuffer, 1);
	buf->fd = fd;
	buf->pool = pool;
	buf->priority = priority;
	buf->max_size = max_size;
	return buf;
}

IOBuffer *io_buffer_create_file(int fd, Pool pool, unsigned int max_size)
{
	IOBuffer *buf;

	buf = io_buffer_create(fd, pool, IO_PRIORITY_DEFAULT, max_size);
	buf->file = TRUE;
        return buf;
}

void io_buffer_destroy(IOBuffer *buf)
{
	if (buf == NULL)
		return;

        if (buf->io != NULL)
		io_remove(buf->io);
        p_free(buf->pool, buf->buffer);
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
}

IOBuffer *io_buffer_set_pool(IOBuffer *buf, Pool pool)
{
	IOBuffer *newbuf;

        i_assert(buf != NULL);
        i_assert(pool != NULL);

	newbuf = p_new(pool, IOBuffer, 1);
	memcpy(newbuf, buf, sizeof(IOBuffer));

	newbuf->pool = pool;
	newbuf->buffer = p_malloc(pool, buf->size);
	memcpy(newbuf->buffer, buf->buffer + buf->skip,
	       buf->size - buf->skip);

	newbuf->cr_lookup_pos -= newbuf->skip;
        newbuf->pos -= newbuf->skip;
	newbuf->skip = 0;

        p_free(buf->pool, buf->buffer);
        p_free(buf->pool, buf);
        return newbuf;
}

void io_buffer_set_max_size(IOBuffer *buf, unsigned int max_size)
{
        buf->max_size = max_size;
}

void io_buffer_set_send_blocking(IOBuffer *buf, unsigned int max_size,
				 int timeout_msecs, TimeoutFunc timeout_func,
				 void *user_data)
{
	i_assert(!buf->receive);

	buf->transmit = TRUE;
	buf->timeout_msecs = timeout_msecs;
	buf->timeout_func = timeout_func;
	buf->timeout_user_data = user_data;
	buf->blocking = max_size > 0;
	buf->max_size = max_size;
}

static int my_write(int fd, const void *buf, unsigned int size)
{
	int ret;

	i_assert(size <= INT_MAX);

	if (size == 0)
		return 1;

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
	} else {
		buf->transfd += ret;
		buf->skip += ret;
		if (buf->skip == buf->pos) {
			/* everything sent */
			buf->skip = buf->pos = 0;

			/* call flush function */
			if (buf->flush_func != NULL) {
				buf->flush_func(buf->flush_user_data, buf);
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

typedef struct {
	IOLoop ioloop;
	IOBuffer *buf;

	const char *data;
	unsigned int size;

	int in_fd;
	off_t offset;

	int timeout;
} IOBufferBlockData;

static void block_loop_send(IOBufferBlockData *bd)
{
	int ret;

	if (bd->buf->skip != bd->buf->pos) {
		buf_send_real(bd->buf);
	} else {
		/* send the data */
		ret = !bd->buf->file ?
			net_transmit(bd->buf->fd, bd->data, bd->size) :
			my_write(bd->buf->fd, bd->data, bd->size);

		if (ret < 0) {
			bd->buf->closed = TRUE;
		} else {
			bd->data += ret;
			bd->size -= ret;
		}
	}

	if (bd->buf->closed || bd->size == 0)
		io_loop_stop(bd->ioloop);
}

static void block_loop_timeout(void *user_data, Timeout timeout __attr_unused__)
{
	IOBufferBlockData *data = user_data;

	data->timeout = TRUE;
	io_loop_stop(data->ioloop);
}

static int io_buffer_ioloop(IOBuffer *buf, IOBufferBlockData *bd,
			    void (*send_func)(IOBufferBlockData *bd))
{
	Timeout to;

	/* close old IO */
	if (buf->io != NULL)
		io_remove(buf->io);

	/* create a new I/O loop */
	bd->ioloop = io_loop_create();
	bd->buf = buf;

	buf->io = io_add(buf->fd, IO_WRITE, (IOFunc) send_func, bd);
	to = buf->timeout_msecs <= 0 ? NULL :
		timeout_add(buf->timeout_msecs, block_loop_timeout, bd);

	io_loop_run(bd->ioloop);

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
		if (bd->timeout && buf->timeout_func != NULL) {
			/* call user-given timeout function */
			buf->timeout_func(buf->timeout_user_data, to);
		}
		timeout_remove(to);
	}

	io_loop_destroy(bd->ioloop);
	return bd->size > 0 ? -1 : 1;
}

static int io_buffer_send_blocking(IOBuffer *buf, const void *data,
				   unsigned int size)
{
        IOBufferBlockData bd;

	memset(&bd, 0, sizeof(IOBufferBlockData));

	bd.data = data;
	bd.size = size;

        return io_buffer_ioloop(buf, &bd, block_loop_send);
}

void io_buffer_cork(IOBuffer *buf)
{
	i_assert(!buf->receive);

	if (!buf->file && !buf->corked) {
		net_set_cork(buf->fd, TRUE);
		buf->corked = TRUE;
	}
}

static void buffer_alloc_more(IOBuffer *buf, unsigned int size)
{
	buf->size = buf->pos+size;
	buf->size = buf->size <= IO_BUFFER_MIN_SIZE ? IO_BUFFER_MIN_SIZE :
		nearest_power(buf->size);

	if (buf->max_size > 0 && buf->size > buf->max_size)
		buf->size = buf->max_size;

	buf->buffer = p_realloc(buf->pool, buf->buffer, buf->size);
	if (buf->buffer == NULL) {
		/* pool limit exceeded */
		buf->pos = buf->size = 0;
	}
}

static inline void io_buffer_compress(IOBuffer *buf)
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

int io_buffer_send(IOBuffer *buf, const void *data, unsigned int size)
{
	int ret;

	i_assert(!buf->receive);
        i_assert(data != NULL);
	i_assert(size < INT_MAX);
	buf->transmit = TRUE;

	if (buf->closed)
                return -1;

	if (buf->pos == 0) {
		/* buffer is empty, try to send the data immediately */
		ret = buf->file ? my_write(buf->fd, data, size) :
			net_transmit(buf->fd, data, size);
		if (ret < 0) {
			/* disconnected */
			buf->closed = TRUE;
			return -1;
		}

		buf->transfd += ret;
		data = (const char *) data + ret;
                size -= ret;
	}

	if (size == 0)
		return 1;

	if (io_buffer_get_space(buf, size) == NULL) {
		if (buf->blocking) {
			/* if we don't have space, we block */
			return io_buffer_send_blocking(buf, data, size);
		}
		return -2;
	}

	/* add to buffer */
	memcpy(buf->buffer + buf->pos, data, size);
	buf->pos += size;

	if (buf->io == NULL) {
		buf->io = io_add_priority(buf->fd, buf->priority, IO_WRITE,
					  (IOFunc) buf_send, buf);
	}
        return 1;
}

#ifdef HAVE_SYS_SENDFILE_H
static void block_loop_sendfile(IOBufferBlockData *bd)
{
	int ret;

	ret = sendfile(bd->buf->fd, bd->in_fd, &bd->offset, bd->size);
	if (ret < 0) {
		if (errno != EINTR && errno != EAGAIN)
			bd->buf->closed = TRUE;
		ret = 0;
	}

	bd->size -= ret;
	if (bd->buf->closed || bd->size == 0)
		io_loop_stop(bd->ioloop);
}
#endif

int io_buffer_send_file(IOBuffer *buf, int fd, off_t offset,
			const void *data, unsigned int size)
{
#ifdef HAVE_SYS_SENDFILE_H
        IOBufferBlockData bd;
	int ret;
#endif

	i_assert(fd >= 0);
	i_assert(data != NULL);
	i_assert(size < INT_MAX);

#ifdef HAVE_SYS_SENDFILE_H
	io_buffer_send_flush(buf);

	/* first try if we can do it with a single sendfile() call */
	ret = sendfile(buf->fd, fd, &offset, size);
	if (ret < 0) {
		if (errno != EINTR && errno != EAGAIN)
			return -1;
		ret = 0;
	}

	if ((unsigned int) ret == size)
		return 1;

	if (buf->blocking) {
		memset(&bd, 0, sizeof(IOBufferBlockData));

		bd.in_fd = fd;
		bd.offset = offset + ret;
		bd.size = size - ret;

		return io_buffer_ioloop(buf, &bd, block_loop_sendfile);
	} else {
		data = (char *) data + ret;
		size -= ret;
	}
#endif
	return io_buffer_send(buf, data, size);
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
				   void *user_data)
{
	i_assert(!buf->receive);

	if (buf->skip == buf->pos) {
		func(user_data, buf);
		return;
	}

	buf->flush_func = func;
	buf->flush_user_data = user_data;
}

int io_buffer_read_max(IOBuffer *buf, unsigned int size)
{
	int ret;

	i_assert(size <= INT_MAX || size == UINT_MAX);
	i_assert(!buf->transmit);
	buf->receive = TRUE;

	if (buf->closed)
                return -1;

	if (buf->pos == buf->size) {
		if (buf->skip > 0) {
			/* remove the unused bytes from beginning of buffer */
                        io_buffer_compress(buf);
		} else if (buf->max_size == 0 || buf->size < buf->max_size) {
			/* buffer is full - grow it */
			buffer_alloc_more(buf, IO_BUFFER_MIN_SIZE);
		}

		if (buf->pos == buf->size)
                        return -2; /* buffer full */
	}

        /* fill the buffer */
	if (size == UINT_MAX || buf->size-buf->pos < size)
		size = buf->size - buf->pos;

	if (!buf->file) {
		ret = net_receive(buf->fd, buf->buffer + buf->pos,
				  buf->size - buf->pos);
	} else {
                ret = read(buf->fd, buf->buffer + buf->pos,
			   buf->size - buf->pos);
		if (ret == 0)
			ret = -1; /* EOF */
		else if (ret < 0 && (errno == EINTR || errno == EAGAIN))
                        ret = 0;
	}

	if (ret < 0) {
		/* disconnected */
                return -1;
	}

        buf->transfd += ret;
	buf->pos += ret;
        return ret;
}

int io_buffer_read(IOBuffer *buf)
{
        return io_buffer_read_max(buf, UINT_MAX);
}

/* skip the first LF, if it exists */
static inline void io_buffer_skip_lf(IOBuffer *buf)
{
	if (!buf->last_cr || buf->skip >= buf->pos)
		return;

	if (buf->buffer[buf->skip] == 10) {
		if (buf->skip == buf->cr_lookup_pos)
			buf->cr_lookup_pos++;
		buf->skip++;
	}
	buf->last_cr = FALSE;
}

char *io_buffer_next_line(IOBuffer *buf)
{
	unsigned char *ret_buf;
        unsigned int i;

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
			buf->skip = i;
                        break;
		}
	}

	buf->cr_lookup_pos = i;
        return (char *) ret_buf;
}

unsigned char *io_buffer_get_data(IOBuffer *buf, unsigned int *size)
{
	io_buffer_skip_lf(buf);

	if (buf->skip >= buf->pos) {
		*size = 0;
		return NULL;
	}

        *size = buf->pos - buf->skip;
        return buf->buffer + buf->skip;
}

unsigned char *io_buffer_get_space(IOBuffer *buf, unsigned int size)
{
	i_assert(size <= INT_MAX);
	i_assert(!buf->receive);
	buf->transmit = TRUE;

	/* make sure we have enough space in buffer */
	if (buf->size - buf->pos < size && buf->skip > 0) {
		/* remove the unused bytes from beginning of buffer */
		io_buffer_compress(buf);
	}

	if (buf->size - buf->pos < size &&
	    (buf->max_size == 0 || size <= buf->max_size - buf->pos)) {
		/* allocate more space */
                buffer_alloc_more(buf, size);
	}

	if (buf->size - buf->pos < size)
                return NULL;

        return buf->buffer + buf->pos;
}

int io_buffer_send_buffer(IOBuffer *buf, unsigned int size)
{
	int ret;

	i_assert(size <= INT_MAX);
	i_assert(!buf->receive);

	if (buf->pos == 0) {
		/* buffer is empty, try to send the data immediately */
		ret = buf->file ? my_write(buf->fd, buf->buffer, size) :
			net_transmit(buf->fd, buf->buffer, size);
		if (ret < 0) {
			/* disconnected */
                        buf->closed = TRUE;
			return -1;
		}

		buf->transfd += ret;
		if ((unsigned int) ret == size) {
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

int io_buffer_set_data(IOBuffer *buf, const void *data, unsigned int size)
{
	io_buffer_reset(buf);

	if (buf->size < size) {
		buffer_alloc_more(buf, size);
		if (buf->size < size)
                        return -2;
	}

	memcpy(buf->buffer, data, size);
	buf->pos = size;
        buf->transfd += size;
        return 1;
}

int io_buffer_is_empty(IOBuffer *buf)
{
        return buf->skip >= buf->pos;
}
