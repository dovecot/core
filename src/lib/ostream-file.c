/*
   ostream-file.c : Output stream handling for files

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
#include "ioloop.h"
#include "network.h"
#include "sendfile-util.h"
#include "istream.h"
#include "ostream-internal.h"

#include <unistd.h>
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif

#define O_STREAM_MIN_SIZE 4096

#define IS_STREAM_EMPTY(fstream) \
	((fstream)->head == (fstream)->tail && !(fstream)->full)

#define MAX_SSIZE_T(size) \
	((size) < SSIZE_T_MAX ? (size_t)(size) : SSIZE_T_MAX)

struct file_ostream {
	struct _ostream ostream;

	int fd;
	int priority;
	struct io *io;

	unsigned char *buffer; /* ring-buffer */
	size_t buffer_size, max_buffer_size;
	size_t head, tail; /* first unsent/unused byte */

	int timeout_msecs;
	void (*timeout_func)(void *);
	void *timeout_context;

	unsigned int full:1; /* if head == tail, is buffer empty or full? */
	unsigned int corked:1;
	unsigned int no_socket_cork:1;
	unsigned int autoclose_fd:1;
};

static void stream_closed(struct file_ostream *fstream)
{
	if (fstream->autoclose_fd && fstream->fd != -1) {
		if (close(fstream->fd) < 0)
			i_error("file_ostream.close() failed: %m");
		fstream->fd = -1;
	}

	if (fstream->io != NULL) {
		io_remove(fstream->io);
		fstream->io = NULL;
	}

	fstream->ostream.ostream.closed = TRUE;
}

static void _close(struct _iostream *stream)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;

	/* flush output before really closing it */
	o_stream_flush(&fstream->ostream.ostream);

	stream_closed(fstream);
}

static void _destroy(struct _iostream *stream)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;

	p_free(fstream->ostream.iostream.pool, fstream->buffer);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;

	fstream->max_buffer_size = max_size;
}

static void _set_blocking(struct _iostream *stream, int timeout_msecs,
			  void (*timeout_func)(void *), void *context)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;

	fstream->timeout_msecs = timeout_msecs;
	fstream->timeout_func = timeout_func;
	fstream->timeout_context = context;

	net_set_nonblock(fstream->fd, timeout_msecs == 0);

	if (timeout_msecs != 0)
		alarm_hup_init();
}

static void _cork(struct _ostream *stream)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;

	if (!fstream->corked) {
		if (!fstream->no_socket_cork) {
			if (net_set_cork(fstream->fd, TRUE) < 0)
				fstream->no_socket_cork = TRUE;
		}
		fstream->corked = TRUE;
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

static void update_buffer(struct file_ostream *fstream, size_t size)
{
	size_t used;

	if (IS_STREAM_EMPTY(fstream))
		return;

	if (fstream->head < fstream->tail) {
		/* ...HXXXT... */
		used = fstream->tail - fstream->head;
		fstream->head += I_MIN(used, size);
	} else {
		/* XXXT...HXXX */
		used = fstream->buffer_size - fstream->head;
		if (size > used) {
			size -= used;
			if (size < fstream->tail)
				fstream->head = size;
			else {
				/* whole buffer is sent */
				fstream->head = fstream->tail = 0;
			}
		} else {
			fstream->head += I_MIN(used, size);
		}

		fstream->full = FALSE;
	}

	if (fstream->head == fstream->tail)
		fstream->head = fstream->tail = 0;

	if (fstream->head == fstream->buffer_size)
		fstream->head = 0;
}

/* NOTE: modifies iov */
static ssize_t
o_stream_writev(struct file_ostream *fstream, struct iovec *iov, int iov_size)
{
	ssize_t ret;

	while (iov->iov_len == 0 && iov_size > 0) {
		iov++;
		iov_size--;
	}

	i_assert(iov_size > 0);

	ret = writev(fstream->fd, iov, iov_size);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return 0;
		stream_closed(fstream);
		return -1;
	}

	update_iovec(iov, iov_size, ret);
	update_buffer(fstream, ret);
	fstream->ostream.ostream.offset += ret;

	return ret;
}

/* returns how much of vector was used */
static int o_stream_fill_iovec(struct file_ostream *fstream,
			       struct iovec iov[2])
{
	if (IS_STREAM_EMPTY(fstream))
		return 0;

	if (fstream->head < fstream->tail) {
		iov[0].iov_base = fstream->buffer + fstream->head;
		iov[0].iov_len = fstream->tail - fstream->head;
		return 1;
	} else {
		iov[0].iov_base = fstream->buffer + fstream->head;
		iov[0].iov_len = fstream->buffer_size - fstream->head;
		if (fstream->tail == 0)
			return 1;
		else {
			iov[1].iov_base = fstream->buffer;
			iov[1].iov_len = fstream->tail;
			return 2;
		}
	}
}

static int o_stream_send_blocking(struct file_ostream *fstream,
				  const void *data, size_t size)
{
	time_t timeout_time;
	struct iovec iov[3];
	int iov_len, first;

	iov_len = o_stream_fill_iovec(fstream, iov);
	if (size > 0) {
		iov[iov_len].iov_base = (void *) data;
		iov[iov_len].iov_len = size;
		iov_len++;
	}

	first = TRUE;

	timeout_time = GET_TIMEOUT_TIME(fstream);
	while (iov[iov_len-1].iov_len != 0) {
		if (first)
			first = FALSE;
		else if (timeout_time > 0 && time(NULL) > timeout_time) {
			/* timeouted */
			if (fstream->timeout_func != NULL)
				fstream->timeout_func(fstream->timeout_context);
			fstream->ostream.ostream.stream_errno = EAGAIN;
			return -1;
		}

		if (o_stream_writev(fstream, iov, iov_len) < 0)
			return -1;
	}

        return 1;
}

static int buffer_flush(struct file_ostream *fstream)
{
	struct iovec iov[2];
	int iov_len;

	if (!IS_STREAM_EMPTY(fstream)) {
		iov_len = o_stream_fill_iovec(fstream, iov);
		if (o_stream_writev(fstream, iov, iov_len) < 0)
			return -1;

		if (!IS_STREAM_EMPTY(fstream)) {
			if (o_stream_send_blocking(fstream, NULL, 0) < 0)
				return -1;
		}
	}

	return 1;
}

static int _flush(struct _ostream *stream)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;
	int ret;

	ret = buffer_flush(fstream);

	if (fstream->corked) {
		/* remove cork */
		if (!fstream->no_socket_cork) {
			if (net_set_cork(fstream->fd, FALSE) < 0)
				i_error("net_set_cork() failed: %m");
		}
		fstream->corked = FALSE;
	}

	return ret;
}

static size_t get_unused_space(struct file_ostream *fstream)
{
	if (fstream->head > fstream->tail) {
		/* XXXT...HXXX */
		return fstream->head - fstream->tail;
	} else if (fstream->head < fstream->tail) {
		/* ...HXXXT... */
		return (fstream->buffer_size - fstream->tail) + fstream->head;
	} else {
		/* either fully unused or fully used */
		return fstream->full ? 0 : fstream->buffer_size;
	}
}

static int _have_space(struct _ostream *stream, size_t size)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;
	size_t unused;

	unused = get_unused_space(fstream);
	if (size <= unused)
		return 1;

	if (fstream->max_buffer_size == 0)
		return 1;

	unused += (fstream->max_buffer_size - fstream->buffer_size);
	return size <= unused ? 1 : 0;
}

static int _seek(struct _ostream *stream, uoff_t offset)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;
	off_t ret;

	if (offset > OFF_T_MAX) {
		stream->ostream.stream_errno = EINVAL;
		return -1;
	}

	ret = lseek(fstream->fd, (off_t)offset, SEEK_SET);
	if (ret < 0) {
		stream->ostream.stream_errno = errno;
		return -1;
	}

	if (ret != (off_t)offset) {
		stream->ostream.stream_errno = EINVAL;
		return -1;
	}

	stream->ostream.stream_errno = 0;
	stream->ostream.offset = offset;
	return 1;
}

static void o_stream_grow_buffer(struct file_ostream *fstream, size_t bytes)
{
	size_t size, head_size;

	size = nearest_power(fstream->buffer_size + bytes);
	if (fstream->max_buffer_size != 0) {
		if (size > fstream->max_buffer_size) {
			/* limit the size */
			size = fstream->max_buffer_size;
		} else if (fstream->corked) {
			/* use the largest possible buffer with corking */
			size = fstream->max_buffer_size;
		}
	}

	if (size == fstream->buffer_size)
		return;

	fstream->buffer = p_realloc(fstream->ostream.iostream.pool,
				    fstream->buffer,
				    fstream->buffer_size, size);

	if (fstream->tail <= fstream->head && !IS_STREAM_EMPTY(fstream)) {
		head_size = I_MIN(fstream->head, size - fstream->buffer_size);
		memcpy(fstream->buffer + fstream->buffer_size, fstream->buffer,
		       head_size);

		if (head_size == fstream->head)
			fstream->tail = fstream->buffer_size + head_size;
		else {
			memmove(fstream->buffer, fstream->buffer + head_size,
				fstream->head - head_size);
			fstream->tail = fstream->head - head_size;
		}
	}

	fstream->full = FALSE;
	fstream->buffer_size = size;
}

static void stream_send_io(void *context, int fd __attr_unused__,
			   struct io *io __attr_unused__)
{
	struct file_ostream *fstream = context;
	struct iovec iov[2];
	int iov_len;

	iov_len = o_stream_fill_iovec(fstream, iov);

	if (iov_len == 0 || o_stream_writev(fstream, iov, iov_len) < 0 ||
	    iov[iov_len-1].iov_len == 0) {
		/* error / all sent */
		io_remove(fstream->io);
                fstream->io = NULL;
	}
}

static size_t o_stream_add(struct file_ostream *fstream,
			   const void *data, size_t size)
{
	size_t unused, sent;
	int i;

	unused = get_unused_space(fstream);
	if (unused < size)
		o_stream_grow_buffer(fstream, size-unused);

	sent = 0;
	for (i = 0; i < 2 && sent < size && !fstream->full; i++) {
		unused = fstream->tail >= fstream->head ?
			fstream->buffer_size - fstream->tail :
			fstream->head - fstream->tail;

		if (unused > size-sent)
			unused = size-sent;
		memcpy(fstream->buffer + fstream->tail, data, unused);
		sent += unused;

		fstream->tail += unused;
		if (fstream->tail == fstream->buffer_size)
			fstream->tail = 0;

		if (fstream->head == fstream->tail)
			fstream->full = TRUE;
	}

	if (sent != 0 && fstream->io == NULL && !fstream->corked) {
		fstream->io = io_add_priority(fstream->fd, fstream->priority,
					      IO_WRITE, stream_send_io,
					      fstream);
	}

	i_assert(!STREAM_IS_BLOCKING(fstream) || sent == size);
	return sent;
}

static ssize_t _send(struct _ostream *stream, const void *data, size_t size)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;
	struct iovec iov;
	ssize_t ret;

	i_assert(size <= SSIZE_T_MAX);

	stream->ostream.stream_errno = 0;

	/* never try sending immediately if fd is blocking,
	   so we don't need to deal with timeout issues here */
	if (IS_STREAM_EMPTY(fstream) && !STREAM_IS_BLOCKING(fstream) &&
	    (!fstream->corked || !_have_space(stream, size))) {
		iov.iov_base = (void *) data;
		iov.iov_len = size;
		ret = o_stream_writev(fstream, &iov, 1);
		if (ret < 0 || (size_t)ret == size)
			return ret;

		data = (const char *) data + ret;
		size -= ret;
	}

	if (!_have_space(stream, size) && STREAM_IS_BLOCKING(fstream)) {
		/* send it blocking */
		if (o_stream_send_blocking(fstream, data, size) < 0)
			return -1;
		return (ssize_t)size;
	} else {
		/* buffer it, at least partly */
		return (ssize_t)o_stream_add(fstream, data, size);
	}
}

static off_t io_stream_sendfile(struct _ostream *outstream,
				struct istream *instream)
{
	struct file_ostream *foutstream = (struct file_ostream *) outstream;
	time_t timeout_time;
	uoff_t start_offset;
	uoff_t offset, send_size;
	ssize_t ret;
	int in_fd, first;

	in_fd = i_stream_get_fd(instream);
	if (in_fd == -1) {
		outstream->ostream.stream_errno = EINVAL;
		return -1;
	}

	/* set timeout time before flushing existing buffer which may block */
	timeout_time = GET_TIMEOUT_TIME(foutstream);
        start_offset = instream->v_offset;

	/* flush out any data in buffer */
	if (buffer_flush(foutstream) < 0)
		return -1;

	first = TRUE;
	for (;;) {
		if (first)
			first = FALSE;
		else if (timeout_time > 0 && time(NULL) > timeout_time) {
			/* timeouted */
			if (foutstream->timeout_func != NULL) {
				foutstream->timeout_func(
					foutstream->timeout_context);
			}
			outstream->ostream.stream_errno = EAGAIN;
			return -1;
		}

		offset = instream->start_offset + instream->v_offset;
		send_size = instream->v_limit - instream->v_offset;

		ret = safe_sendfile(foutstream->fd, in_fd, &offset,
				    MAX_SSIZE_T(send_size));
		if (ret < 0) {
			if (errno != EINTR && errno != EAGAIN) {
				outstream->ostream.stream_errno = errno;
				if (errno != EINVAL) {
					/* close only if error wasn't because
					   sendfile() isn't supported */
					stream_closed(foutstream);
				}
				return -1;
			}

			if (!STREAM_IS_BLOCKING(foutstream)) {
				/* don't block */
				break;
			}
			ret = 0;
		}

		i_stream_skip(instream, (size_t)ret);
		outstream->ostream.offset += ret;

		if ((uoff_t)ret == send_size) {
			/* yes, all sent */
			break;
		}
	}

	return (off_t) (instream->v_offset - start_offset);
}

static off_t io_stream_copy(struct _ostream *outstream,
			    struct istream *instream)
{
	struct file_ostream *foutstream = (struct file_ostream *) outstream;
	time_t timeout_time;
	uoff_t start_offset;
	struct iovec iov[3];
	int iov_len;
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	int pos;

	timeout_time = GET_TIMEOUT_TIME(foutstream);
	iov_len = o_stream_fill_iovec(foutstream, iov);

        start_offset = instream->v_offset;
	for (;;) {
		(void)i_stream_read_data(instream, &data, &size,
					 O_STREAM_MIN_SIZE-1);

		if (size == 0) {
			/* all sent */
			break;
		}

		pos = iov_len++;
		iov[pos].iov_base = (void *) data;
		iov[pos].iov_len = size;

		ret = o_stream_writev(foutstream, iov, iov_len);
		if (ret < 0) {
			/* error */
			return -1;
		}

		if (ret == 0 && !STREAM_IS_BLOCKING(foutstream)) {
			/* don't block */
			break;
		}

		if (timeout_time > 0 && time(NULL) > timeout_time) {
			/* timeouted */
			if (foutstream->timeout_func != NULL) {
				foutstream->timeout_func(
					foutstream->timeout_context);
			}
			outstream->ostream.stream_errno = EAGAIN;
			return -1;
		}

		i_stream_skip(instream, size - iov[pos].iov_len);
		iov_len--;

		/* if we already sent the iov[0] and iov[1], we
		   can just remove them from future calls */
		while (iov_len > 0 && iov[0].iov_len == 0) {
			iov[0] = iov[1];
			if (iov_len > 1) iov[1] = iov[2];
			iov_len--;
		}
	}

	return (off_t) (instream->v_offset - start_offset);
}

static off_t _send_istream(struct _ostream *outstream, struct istream *instream)
{
	off_t ret;

	i_assert(instream->v_limit <= OFF_T_MAX);
	i_assert(instream->v_offset <= instream->v_limit);

	if (instream->v_offset == instream->v_limit)
		return 0;

	ret = io_stream_sendfile(outstream, instream);
	if (ret >= 0 || outstream->ostream.stream_errno != EINVAL)
		return ret;

	/* sendfile() not supported (with this fd), fallback to
	   regular sending */

	outstream->ostream.stream_errno = 0;
	return io_stream_copy(outstream, instream);
}

struct ostream *
o_stream_create_file(int fd, pool_t pool, size_t max_buffer_size,
		     int priority, int autoclose_fd)
{
	struct file_ostream *fstream;

	fstream = p_new(pool, struct file_ostream, 1);
	fstream->fd = fd;
	fstream->priority = priority;
	fstream->max_buffer_size = max_buffer_size;
	fstream->autoclose_fd = autoclose_fd;

	fstream->ostream.iostream.close = _close;
	fstream->ostream.iostream.destroy = _destroy;
	fstream->ostream.iostream.set_max_buffer_size = _set_max_buffer_size;
	fstream->ostream.iostream.set_blocking = _set_blocking;

	fstream->ostream.cork = _cork;
	fstream->ostream.flush = _flush;
	fstream->ostream.have_space = _have_space;
	fstream->ostream.seek = _seek;
	fstream->ostream.send = _send;
	fstream->ostream.send_istream = _send_istream;

	return _o_stream_create(&fstream->ostream, pool);
}
