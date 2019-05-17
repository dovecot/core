/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "ioloop.h"
#include "write-full.h"
#include "net.h"
#include "sendfile-util.h"
#include "istream.h"
#include "istream-private.h"
#include "ostream-file-private.h"

#include <unistd.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif

/* try to keep the buffer size within 4k..128k. ReiserFS may actually return
   128k as optimal size. */
#define DEFAULT_OPTIMAL_BLOCK_SIZE IO_BLOCK_SIZE
#define MAX_OPTIMAL_BLOCK_SIZE (128*1024)

#define IS_STREAM_EMPTY(fstream) \
	((fstream)->head == (fstream)->tail && !(fstream)->full)

#define MAX_SSIZE_T(size) \
	((size) < SSIZE_T_MAX ? (size_t)(size) : SSIZE_T_MAX)

static void stream_send_io(struct file_ostream *fstream);
static struct ostream * o_stream_create_fd_common(int fd,
		size_t max_buffer_size, bool autoclose_fd);

static void stream_closed(struct file_ostream *fstream)
{
	io_remove(&fstream->io);

	if (fstream->autoclose_fd && fstream->fd != -1) {
		if (close(fstream->fd) < 0) {
			i_error("file_ostream.close(%s) failed: %m",
				o_stream_get_name(&fstream->ostream.ostream));
		}
	}
	fstream->fd = -1;

	fstream->ostream.ostream.closed = TRUE;
}

void o_stream_file_close(struct iostream_private *stream,
				bool close_parent ATTR_UNUSED)
{
	struct file_ostream *fstream = (struct file_ostream *)stream;

	stream_closed(fstream);
}

static void o_stream_file_destroy(struct iostream_private *stream)
{
	struct file_ostream *fstream = (struct file_ostream *)stream;

	i_free(fstream->buffer);
}

static size_t file_buffer_get_used_size(struct file_ostream *fstream)
{
	if (fstream->head == fstream->tail)
		return fstream->full ? fstream->buffer_size : 0;
	else if (fstream->head < fstream->tail) {
		/* ...HXXXT... */
		return fstream->tail - fstream->head;
	} else {
		/* XXXT...HXXX */
		return fstream->tail +
			(fstream->buffer_size - fstream->head);
	}
}

static void update_buffer(struct file_ostream *fstream, size_t size)
{
	size_t used;

	if (IS_STREAM_EMPTY(fstream) || size == 0)
		return;

	if (fstream->head < fstream->tail) {
		/* ...HXXXT... */
		used = fstream->tail - fstream->head;
		i_assert(size <= used);
		fstream->head += size;
	} else {
		/* XXXT...HXXX */
		used = fstream->buffer_size - fstream->head;
		if (size > used) {
			size -= used;
			i_assert(size <= fstream->tail);
			fstream->head = size;
		} else {
			fstream->head += size;
		}

		fstream->full = FALSE;
	}

	if (fstream->head == fstream->tail)
		fstream->head = fstream->tail = 0;

	if (fstream->head == fstream->buffer_size)
		fstream->head = 0;
}

static void o_stream_socket_cork(struct file_ostream *fstream)
{
	if (fstream->ostream.corked && !fstream->socket_cork_set) {
		if (!fstream->no_socket_cork) {
			if (net_set_cork(fstream->fd, TRUE) < 0)
				fstream->no_socket_cork = TRUE;
			else
				fstream->socket_cork_set = TRUE;
		}
	}
}

static int o_stream_lseek(struct file_ostream *fstream)
{
	off_t ret;

	if (fstream->real_offset == fstream->buffer_offset)
		return 0;

	ret = lseek(fstream->fd, (off_t)fstream->buffer_offset, SEEK_SET);
	if (ret < 0) {
		io_stream_set_error(&fstream->ostream.iostream,
				    "lseek() failed: %m");
		fstream->ostream.ostream.stream_errno = errno;
		return -1;
	}

	if (ret != (off_t)fstream->buffer_offset) {
		io_stream_set_error(&fstream->ostream.iostream,
				    "lseek() returned wrong value");
		fstream->ostream.ostream.stream_errno = EINVAL;
		return -1;
	}
	fstream->real_offset = fstream->buffer_offset;
	return 0;
}

ssize_t o_stream_file_writev(struct file_ostream *fstream,
				   const struct const_iovec *iov,
				   unsigned int iov_count)
{
	ssize_t ret;
	size_t size, sent;
	unsigned int i;

	if (iov_count == 1) {
		i_assert(iov->iov_len > 0);

		if (!fstream->file ||
		    fstream->real_offset == fstream->buffer_offset) {
			ret = write(fstream->fd, iov->iov_base, iov->iov_len);
			if (ret > 0)
				fstream->real_offset += ret;
		} else {
			ret = pwrite(fstream->fd, iov->iov_base, iov->iov_len,
				     fstream->buffer_offset);
		}
	} else {
		if (o_stream_lseek(fstream) < 0)
			return -1;

		sent = 0;
		while (iov_count > IOV_MAX) {
			size = 0;
			for (i = 0; i < IOV_MAX; i++)
				size += iov[i].iov_len;

			ret = writev(fstream->fd, (const struct iovec *)iov,
				     IOV_MAX);
			if (ret != (ssize_t)size) {
				break;
			}

			fstream->real_offset += ret;
			fstream->buffer_offset += ret;
			sent += ret;
			iov += IOV_MAX;
			iov_count -= IOV_MAX;
		}

		if (iov_count <= IOV_MAX) {
			size = 0;
			for (i = 0; i < iov_count; i++)
				size += iov[i].iov_len;

			ret = writev(fstream->fd, (const struct iovec *)iov,
				     iov_count);
		}
		if (ret > 0) {
			fstream->real_offset += ret;
			ret += sent;
		} else if (!fstream->file && sent > 0) {
			/* return what we managed to get sent */
			ret = sent;
		}
	}
	return ret;
}

static ssize_t
o_stream_file_writev_full(struct file_ostream *fstream,
				   const struct const_iovec *iov,
				   unsigned int iov_count)
{
	ssize_t ret, ret2;
	size_t size, total_size;
	bool partial;
	unsigned int i;

	for (i = 0, total_size = 0; i < iov_count; i++)
		total_size += iov[i].iov_len;

	o_stream_socket_cork(fstream);
	ret = fstream->writev(fstream, iov, iov_count);
	partial = ret != (ssize_t)total_size;

	if (ret < 0) {
		if (fstream->file) {
			if (errno == EINTR) {
				/* automatically retry */
				return o_stream_file_writev_full(fstream, iov, iov_count);
			}
		} else if (errno == EAGAIN || errno == EINTR) {
			/* try again later */
			return 0;
		}
		fstream->ostream.ostream.stream_errno = errno;
		stream_closed(fstream);
		return -1;
	}
	if (unlikely(ret == 0 && fstream->file)) {
		/* assume out of disk space */
		fstream->ostream.ostream.stream_errno = ENOSPC;
		stream_closed(fstream);
		return -1;
	}
	fstream->buffer_offset += ret;
	if (partial && fstream->file) {
		/* we failed to write everything to a file. either we ran out
		   of disk space or we're writing to NFS. try to write the
		   rest to resolve this. */
		size = ret;
		while (iov_count > 0 && size >= iov->iov_len) {
			size -= iov->iov_len;
			iov++;
			iov_count--;
		}
		i_assert(iov_count > 0);
		if (size == 0)
			ret2 = o_stream_file_writev_full(fstream, iov, iov_count);
		else {
			/* write the first iov separately */
			struct const_iovec new_iov;

			new_iov.iov_base =
				CONST_PTR_OFFSET(iov->iov_base, size);
			new_iov.iov_len = iov->iov_len - size;
			ret2 = o_stream_file_writev_full(fstream, &new_iov, 1);
			if (ret2 > 0) {
				i_assert((size_t)ret2 == new_iov.iov_len);
				/* write the rest */
				if (iov_count > 1) {
					ret += ret2;
					ret2 = o_stream_file_writev_full(fstream, iov + 1,
							       iov_count - 1);
				}
			}
		}
		i_assert(ret2 != 0);
		if (ret2 < 0)
			ret = ret2;
		else
			ret += ret2;
	}
	i_assert(ret < 0 || !fstream->file ||
		 (size_t)ret == total_size);
	return ret;
}

/* returns how much of vector was used */
static int o_stream_fill_iovec(struct file_ostream *fstream,
			       struct const_iovec iov[2])
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

static int buffer_flush(struct file_ostream *fstream)
{
	struct const_iovec iov[2];
	int iov_len;
	ssize_t ret;

	iov_len = o_stream_fill_iovec(fstream, iov);
	if (iov_len > 0) {
		ret = o_stream_file_writev_full(fstream, iov, iov_len);
		if (ret < 0)
			return -1;

		update_buffer(fstream, ret);
	}

	return IS_STREAM_EMPTY(fstream) ? 1 : 0;
}

static void o_stream_tcp_flush_via_nodelay(struct file_ostream *fstream)
{
	if (net_set_tcp_nodelay(fstream->fd, TRUE) < 0) {
		if (errno != ENOTSUP && errno != ENOTSOCK &&
		    errno != ENOPROTOOPT) {
			i_error("file_ostream.net_set_tcp_nodelay(%s, TRUE) failed: %m",
				o_stream_get_name(&fstream->ostream.ostream));
		}
		fstream->no_socket_nodelay = TRUE;
	} else if (net_set_tcp_nodelay(fstream->fd, FALSE) < 0) {
		/* We already successfully enabled TCP_NODELAY, so we're really
		   not expecting any errors here. */
		i_error("file_ostream.net_set_tcp_nodelay(%s, FALSE) failed: %m",
			o_stream_get_name(&fstream->ostream.ostream));
		fstream->no_socket_nodelay = TRUE;
	}
}

static void o_stream_file_cork(struct ostream_private *stream, bool set)
{
	struct file_ostream *fstream = (struct file_ostream *)stream;
	struct iostream_private *iostream = &fstream->ostream.iostream;
	int ret;

	if (stream->corked != set && !stream->ostream.closed) {
		if (set && fstream->io != NULL)
			io_remove(&fstream->io);
		else if (!set) {
			/* buffer flushing might close the stream */
			ret = buffer_flush(fstream);
			stream->last_errors_not_checked = TRUE;
			if (fstream->io == NULL &&
			    (ret == 0 || fstream->flush_pending) &&
			    !stream->ostream.closed) {
				fstream->io = io_add_to(
					io_stream_get_ioloop(iostream),
					fstream->fd, IO_WRITE,
					stream_send_io, fstream);
			}
		}

		if (fstream->socket_cork_set) {
			i_assert(!set);
			if (net_set_cork(fstream->fd, FALSE) < 0)
				fstream->no_socket_cork = TRUE;
			fstream->socket_cork_set = FALSE;
		}
		if (set && !fstream->no_socket_nodelay) {
			/* Uncorking - send all the pending data immediately.
			   Remove nodelay immediately afterwards, so if any
			   output is sent outside corking it may get delayed. */
			o_stream_tcp_flush_via_nodelay(fstream);
		}
		stream->corked = set;
	}
}

static int o_stream_file_flush(struct ostream_private *stream)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;

	return buffer_flush(fstream);
}

static void
o_stream_file_flush_pending(struct ostream_private *stream, bool set)
{
	struct file_ostream *fstream = (struct file_ostream *) stream;
	struct iostream_private *iostream = &fstream->ostream.iostream;

	fstream->flush_pending = set;
	if (set && !stream->corked && fstream->io == NULL) {
		fstream->io = io_add_to(io_stream_get_ioloop(iostream),
					fstream->fd, IO_WRITE,
					stream_send_io, fstream);
	}
}

static size_t get_unused_space(const struct file_ostream *fstream)
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

static size_t
o_stream_file_get_buffer_used_size(const struct ostream_private *stream)
{
	const struct file_ostream *fstream =
		(const struct file_ostream *)stream;

	return fstream->buffer_size - get_unused_space(fstream);
}

static int o_stream_file_seek(struct ostream_private *stream, uoff_t offset)
{
	struct file_ostream *fstream = (struct file_ostream *)stream;

	if (offset > OFF_T_MAX) {
		stream->ostream.stream_errno = EINVAL;
		return -1;
	}
	if (!fstream->file) {
		stream->ostream.stream_errno = ESPIPE;
		return -1;
	}

	if (buffer_flush(fstream) < 0)
		return -1;

	stream->ostream.offset = offset;
	fstream->buffer_offset = offset;
	return 1;
}

static void o_stream_grow_buffer(struct file_ostream *fstream, size_t bytes)
{
	size_t size, new_size, end_size;

	size = nearest_power(fstream->buffer_size + bytes);
	if (size > fstream->ostream.max_buffer_size) {
		/* limit the size */
		size = fstream->ostream.max_buffer_size;
	} else if (fstream->ostream.corked) {
		/* try to use optimal buffer size with corking */
		new_size = I_MIN(fstream->optimal_block_size,
				 fstream->ostream.max_buffer_size);
		if (new_size > size)
			size = new_size;
	}

	if (size <= fstream->buffer_size)
		return;

	fstream->buffer = i_realloc(fstream->buffer,
				    fstream->buffer_size, size);

	if (fstream->tail <= fstream->head && !IS_STREAM_EMPTY(fstream)) {
		/* move head forward to end of buffer */
		end_size = fstream->buffer_size - fstream->head;
		memmove(fstream->buffer + size - end_size,
			fstream->buffer + fstream->head, end_size);
		fstream->head = size - end_size;
	}

	fstream->full = FALSE;
	fstream->buffer_size = size;
}

static void stream_send_io(struct file_ostream *fstream)
{
	struct ostream *ostream = &fstream->ostream.ostream;
	struct iostream_private *iostream = &fstream->ostream.iostream;
	bool use_cork = !fstream->ostream.corked;
	int ret;

	/* Set flush_pending = FALSE first before calling the flush callback,
	   and change it to TRUE only if callback returns 0. That way the
	   callback can call o_stream_set_flush_pending() again and we don't
	   forget it even if flush callback returns 1. */
	fstream->flush_pending = FALSE;

	o_stream_ref(ostream);
	if (use_cork)
		o_stream_cork(ostream);
	if (fstream->ostream.callback != NULL)
		ret = fstream->ostream.callback(fstream->ostream.context);
	else
		ret = o_stream_file_flush(&fstream->ostream);
	if (use_cork)
		o_stream_uncork(ostream);

	if (ret == 0)
		fstream->flush_pending = TRUE;

	if (!fstream->flush_pending && IS_STREAM_EMPTY(fstream)) {
		io_remove(&fstream->io);
	} else if (!fstream->ostream.ostream.closed) {
		/* Add the IO handler if it's not there already. Callback
		   might have just returned 0 without there being any data
		   to be sent. */
		if (fstream->io == NULL) {
			fstream->io = io_add_to(io_stream_get_ioloop(iostream),
						fstream->fd, IO_WRITE,
						stream_send_io, fstream);
		}
	}

	o_stream_unref(&ostream);
}

static size_t o_stream_add(struct file_ostream *fstream,
			   const void *data, size_t size)
{
	struct iostream_private *iostream = &fstream->ostream.iostream;
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
		memcpy(fstream->buffer + fstream->tail,
		       CONST_PTR_OFFSET(data, sent), unused);
		sent += unused;

		fstream->tail += unused;
		if (fstream->tail == fstream->buffer_size)
			fstream->tail = 0;

		if (fstream->head == fstream->tail &&
		    fstream->buffer_size > 0)
			fstream->full = TRUE;
	}

	if (sent != 0 && fstream->io == NULL &&
	    !fstream->ostream.corked && !fstream->file) {
		fstream->io = io_add_to(io_stream_get_ioloop(iostream),
					fstream->fd, IO_WRITE, stream_send_io,
				     	fstream);
	}

	return sent;
}

ssize_t o_stream_file_sendv(struct ostream_private *stream,
				   const struct const_iovec *iov,
				   unsigned int iov_count)
{
	struct file_ostream *fstream = (struct file_ostream *)stream;
	size_t size, total_size, added, optimal_size;
	unsigned int i;
	ssize_t ret = 0;

	for (i = 0, size = 0; i < iov_count; i++)
		size += iov[i].iov_len;
	total_size = size;

	if (size > get_unused_space(fstream) && !IS_STREAM_EMPTY(fstream)) {
		if (o_stream_file_flush(stream) < 0)
			return -1;
	}

	optimal_size = I_MIN(fstream->optimal_block_size,
			     fstream->ostream.max_buffer_size);
	if (IS_STREAM_EMPTY(fstream) &&
	    (!stream->corked || size >= optimal_size)) {
		/* send immediately */
		ret = o_stream_file_writev_full(fstream, iov, iov_count);
		if (ret < 0)
			return -1;

		size = ret;
		while (size > 0 && iov_count > 0 && size >= iov[0].iov_len) {
			size -= iov[0].iov_len;
			iov++;
			iov_count--;
		}

		if (iov_count == 0)
			i_assert(size == 0);
		else {
			added = o_stream_add(fstream,
					CONST_PTR_OFFSET(iov[0].iov_base, size),
					iov[0].iov_len - size);
			ret += added;

			if (added != iov[0].iov_len - size) {
				/* buffer full */
				stream->ostream.offset += ret;
				return ret;
			}

			iov++;
			iov_count--;
		}
	}

	/* buffer it, at least partly */
	for (i = 0; i < iov_count; i++) {
		added = o_stream_add(fstream, iov[i].iov_base, iov[i].iov_len);
		ret += added;
		if (added != iov[i].iov_len)
			break;
	}
	stream->ostream.offset += ret;
	i_assert((size_t)ret <= total_size);
	i_assert((size_t)ret == total_size || !fstream->file);
	return ret;
}

static size_t
o_stream_file_update_buffer(struct file_ostream *fstream,
			    const void *data, size_t size, size_t pos)
{
	size_t avail, copy_size;

	if (fstream->head < fstream->tail) {
		/* ...HXXXT... */
		i_assert(pos < fstream->tail);
		avail = fstream->tail - pos;
	} else {
		/* XXXT...HXXX */
		avail = fstream->buffer_size - pos;
	}
	copy_size = I_MIN(size, avail);
	memcpy(fstream->buffer + pos, data, copy_size);
	data = CONST_PTR_OFFSET(data, copy_size);
	size -= copy_size;

	if (size > 0 && fstream->head >= fstream->tail) {
		/* wraps to beginning of the buffer */
		copy_size = I_MIN(size, fstream->tail);
		memcpy(fstream->buffer, data, copy_size);
		size -= copy_size;
	}
	return size;
}

static int
o_stream_file_write_at(struct ostream_private *stream,
		       const void *data, size_t size, uoff_t offset)
{
	struct file_ostream *fstream = (struct file_ostream *)stream;
	size_t used, pos, skip, left;

	/* update buffer if the write overlaps it */
	used = file_buffer_get_used_size(fstream);
	if (used > 0 &&
	    fstream->buffer_offset < offset + size &&
	    fstream->buffer_offset + used > offset) {
		if (fstream->buffer_offset <= offset) {
			/* updating from the beginning */
			skip = 0;
		} else {
			skip = fstream->buffer_offset - offset;
		}
		pos = (fstream->head + offset + skip - fstream->buffer_offset) %
			fstream->buffer_size;
		left = o_stream_file_update_buffer(fstream,
				CONST_PTR_OFFSET(data, skip), size - skip, pos);
		if (left > 0) {
			/* didn't write all of it */
			if (skip > 0) {
				/* we also have to write a prefix. don't
				   bother with two syscalls, just write all
				   of it in one pwrite(). */
			} else {
				/* write only the suffix */
				size_t update_count = size - left;

				data = CONST_PTR_OFFSET(data, update_count);
				size -= update_count;
				offset += update_count;
			}
		} else if (skip == 0) {
			/* everything done */
			return 0;
		} else {
			/* still have to write prefix */
			size = skip;
		}
	}

	/* we couldn't write everything to the buffer. flush the buffer
	   and pwrite() the rest. */
	if (o_stream_file_flush(stream) < 0)
		return -1;

	if (pwrite_full(fstream->fd, data, size, offset) < 0) {
		stream->ostream.stream_errno = errno;
		stream_closed(fstream);
		return -1;
	}
	return 0;
}

static bool
io_stream_sendfile(struct ostream_private *outstream,
		   struct istream *instream, int in_fd,
		   enum ostream_send_istream_result *res_r)
{
	struct file_ostream *foutstream = (struct file_ostream *)outstream;
	uoff_t in_size, offset, send_size, v_offset, abs_start_offset;
	ssize_t ret;
	bool sendfile_not_supported = FALSE;

	if ((ret = i_stream_get_size(instream, TRUE, &in_size)) < 0) {
		*res_r = OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT;
		return TRUE;
	}
	if (ret == 0) {
		/* size unknown. we can't use sendfile(). */
		return FALSE;
	}

	o_stream_socket_cork(foutstream);

	/* flush out any data in buffer */
	if ((ret = buffer_flush(foutstream)) < 0) {
		*res_r = OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT;
		return TRUE;
	} else if (ret == 0) {
		*res_r = OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT;
		return TRUE;
	}

	if (o_stream_lseek(foutstream) < 0) {
		*res_r = OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT;
		return TRUE;
	}

	v_offset = instream->v_offset;
	abs_start_offset = i_stream_get_absolute_offset(instream) - v_offset;
	while (v_offset < in_size) {
		offset = abs_start_offset + v_offset;
		send_size = in_size - v_offset;

		ret = safe_sendfile(foutstream->fd, in_fd, &offset,
				    MAX_SSIZE_T(send_size));
		if (ret <= 0) {
			if (ret == 0)
				break;
			if (foutstream->file) {
				if (errno == EINTR) {
					/* automatically retry */
					continue;
				}
			} else {
				if (errno == EINTR || errno == EAGAIN) {
					ret = 0;
					break;
				}
			}
			if (errno == EINVAL)
				sendfile_not_supported = TRUE;
			else {
				io_stream_set_error(&outstream->iostream,
						    "sendfile() failed: %m");
				outstream->ostream.stream_errno = errno;
				/* close only if error wasn't because
				   sendfile() isn't supported */
				stream_closed(foutstream);
			}
			break;
		}

		v_offset += ret;
		foutstream->real_offset += ret;
		foutstream->buffer_offset += ret;
		outstream->ostream.offset += ret;
	}

	i_stream_seek(instream, v_offset);
	if (v_offset == in_size) {
		instream->eof = TRUE;
		*res_r = OSTREAM_SEND_ISTREAM_RESULT_FINISHED;
		return TRUE;
	}
	i_assert(ret <= 0);
	if (sendfile_not_supported)
		return FALSE;
	if (ret < 0)
		*res_r = OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT;
	else
		*res_r = OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT;
	return TRUE;
}

static enum ostream_send_istream_result
io_stream_copy_backwards(struct ostream_private *outstream,
			 struct istream *instream, uoff_t in_size)
{
	struct file_ostream *foutstream = (struct file_ostream *)outstream;
	uoff_t in_start_offset, in_offset, in_limit, out_offset;
	const unsigned char *data;
	size_t buffer_size, size, read_size;
	ssize_t ret;

	i_assert(IS_STREAM_EMPTY(foutstream));

	/* figure out optimal buffer size */
	buffer_size = instream->real_stream->buffer_size;
	if (buffer_size == 0 || buffer_size > foutstream->buffer_size) {
		if (foutstream->optimal_block_size > foutstream->buffer_size) {
			o_stream_grow_buffer(foutstream,
					     foutstream->optimal_block_size -
					     foutstream->buffer_size);
		}

		buffer_size = foutstream->buffer_size;
	}

	in_start_offset = instream->v_offset;
	in_offset = in_limit = in_size;
	out_offset = outstream->ostream.offset + (in_offset - in_start_offset);

	while (in_offset > in_start_offset) {
		if (in_offset - in_start_offset <= buffer_size)
			read_size = in_offset - in_start_offset;
		else
			read_size = buffer_size;
		in_offset -= read_size;
		out_offset -= read_size;

		for (;;) {
			i_assert(in_offset <= in_limit);

			i_stream_seek(instream, in_offset);
			read_size = in_limit - in_offset;

			/* FIXME: something's wrong here */
			if (i_stream_read_bytes(instream, &data, &size,
						read_size) == 0)
				i_unreached();
			if (size >= read_size) {
				size = read_size;
				if (instream->mmaped) {
					/* we'll have to write it through
					   buffer or the file gets corrupted */
					i_assert(size <=
						 foutstream->buffer_size);
					memcpy(foutstream->buffer, data, size);
					data = foutstream->buffer;
				}
				break;
			}

			/* buffer too large probably, try with smaller */
			read_size -= size;
			in_offset += read_size;
			out_offset += read_size;
			buffer_size -= read_size;
		}
		in_limit -= size;

		ret = pwrite_full(foutstream->fd, data, size, out_offset);
		if (ret < 0) {
			/* error */
			outstream->ostream.stream_errno = errno;
			return OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT;
		}
		i_stream_skip(instream, size);
	}
	/* make it visible that we're at instream's EOF */
	i_stream_seek(instream, in_size);
	instream->eof = TRUE;

	outstream->ostream.offset += in_size - in_start_offset;
	return OSTREAM_SEND_ISTREAM_RESULT_FINISHED;
}

static enum ostream_send_istream_result
io_stream_copy_same_stream(struct ostream_private *outstream,
			   struct istream *instream)
{
	uoff_t in_size;
	off_t in_abs_offset, ret = 0;

	/* copying data within same fd. we'll have to be careful with
	   seeks and overlapping writes. */
	if ((ret = i_stream_get_size(instream, TRUE, &in_size)) < 0)
		return OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT;
	if (ret == 0) {
		/* if we couldn't find out the size, it means that instream
		   isn't a regular file_istream. we can be reasonably sure that
		   we can copy it safely the regular way. (there's really no
		   other possibility, other than failing completely.) */
		return io_stream_copy(&outstream->ostream, instream);
	}
	i_assert(instream->v_offset <= in_size);

	in_abs_offset = i_stream_get_absolute_offset(instream);
	ret = (off_t)outstream->ostream.offset - in_abs_offset;
	if (ret == 0) {
		/* copying data over itself. we don't really
		   need to do that, just fake it. */
		return OSTREAM_SEND_ISTREAM_RESULT_FINISHED;
	}
	if (ret > 0 && in_size > (uoff_t)ret) {
		/* overlapping */
		i_assert(instream->seekable);
		return io_stream_copy_backwards(outstream, instream, in_size);
	} else {
		/* non-overlapping */
		return io_stream_copy(&outstream->ostream, instream);
	}
}

static enum ostream_send_istream_result
o_stream_file_send_istream(struct ostream_private *outstream,
			   struct istream *instream)
{
	struct file_ostream *foutstream = (struct file_ostream *)outstream;
	bool same_stream;
	int in_fd;
	enum ostream_send_istream_result res;

	in_fd = !instream->readable_fd ? -1 : i_stream_get_fd(instream);
	if (!foutstream->no_sendfile && in_fd != -1 &&
	    in_fd != foutstream->fd && instream->seekable) {
		if (io_stream_sendfile(outstream, instream, in_fd, &res))
			return res;

		/* sendfile() not supported (with this fd), fallback to
		   regular sending. */
		foutstream->no_sendfile = TRUE;
	}

	same_stream = i_stream_get_fd(instream) == foutstream->fd &&
		foutstream->fd != -1;
	if (!same_stream)
		return io_stream_copy(&outstream->ostream, instream);
	return io_stream_copy_same_stream(outstream, instream);
}

static void o_stream_file_switch_ioloop_to(struct ostream_private *stream,
					   struct ioloop *ioloop)
{
	struct file_ostream *fstream = (struct file_ostream *)stream;

	if (fstream->io != NULL)
		fstream->io = io_loop_move_io_to(ioloop, &fstream->io);
}

struct ostream *
o_stream_create_file_common(struct file_ostream *fstream,
	int fd, size_t max_buffer_size, bool autoclose_fd)
{
	struct ostream *ostream;

	fstream->fd = fd;
	fstream->autoclose_fd = autoclose_fd;
	fstream->optimal_block_size = DEFAULT_OPTIMAL_BLOCK_SIZE;

	fstream->ostream.iostream.close = o_stream_file_close;
	fstream->ostream.iostream.destroy = o_stream_file_destroy;

	fstream->ostream.cork = o_stream_file_cork;
	fstream->ostream.flush = o_stream_file_flush;
	fstream->ostream.flush_pending = o_stream_file_flush_pending;
	fstream->ostream.get_buffer_used_size =
		o_stream_file_get_buffer_used_size;
	fstream->ostream.seek = o_stream_file_seek;
	fstream->ostream.sendv = o_stream_file_sendv;
	fstream->ostream.write_at = o_stream_file_write_at;
	fstream->ostream.send_istream = o_stream_file_send_istream;
	fstream->ostream.switch_ioloop_to = o_stream_file_switch_ioloop_to;

	fstream->writev = o_stream_file_writev;

	fstream->ostream.max_buffer_size = max_buffer_size;
	ostream = o_stream_create(&fstream->ostream, NULL, fd);

	if (max_buffer_size == 0)
		fstream->ostream.max_buffer_size = fstream->optimal_block_size;

	return ostream;
}

static void fstream_init_file(struct file_ostream *fstream)
{
	struct stat st;

	fstream->no_sendfile = TRUE;
	if (fstat(fstream->fd, &st) < 0)
		return;

	if ((uoff_t)st.st_blksize > fstream->optimal_block_size) {
		/* use the optimal block size, but with a reasonable limit */
		fstream->optimal_block_size =
			I_MIN(st.st_blksize, MAX_OPTIMAL_BLOCK_SIZE);
	}

	if (S_ISREG(st.st_mode)) {
		fstream->no_socket_cork = TRUE;
		fstream->no_socket_nodelay = TRUE;
		fstream->file = TRUE;
	}
}

static
struct ostream * o_stream_create_fd_common(int fd, size_t max_buffer_size,
		bool autoclose_fd)
{
	struct file_ostream *fstream;
	struct ostream *ostream;
	off_t offset;

	fstream = i_new(struct file_ostream, 1);
	ostream = o_stream_create_file_common
		(fstream, fd, max_buffer_size, autoclose_fd);

	offset = lseek(fd, 0, SEEK_CUR);
	if (offset >= 0) {
		ostream->offset = offset;
		fstream->real_offset = offset;
		fstream->buffer_offset = offset;
		fstream_init_file(fstream);
	} else {
		struct ip_addr local_ip;

		if (net_getsockname(fd, &local_ip, NULL) < 0) {
			/* not a socket */
			fstream->no_sendfile = TRUE;
			fstream->no_socket_cork = TRUE;
			fstream->no_socket_nodelay = TRUE;
		} else if (local_ip.family == 0) {
			/* UNIX domain socket */
			fstream->no_socket_cork = TRUE;
			fstream->no_socket_nodelay = TRUE;
		}
	}

	return ostream;
}

struct ostream *
o_stream_create_fd(int fd, size_t max_buffer_size)
{
	return o_stream_create_fd_common(fd, max_buffer_size, FALSE);
}

struct ostream *
o_stream_create_fd_autoclose(int *fd, size_t max_buffer_size)
{
	struct ostream *ostream = o_stream_create_fd_common(*fd,
			max_buffer_size, TRUE);
	*fd = -1;
	return ostream;
}

struct ostream *
o_stream_create_fd_file(int fd, uoff_t offset, bool autoclose_fd)
{
	struct file_ostream *fstream;
	struct ostream *ostream;

	if (offset == (uoff_t)-1)
		offset = lseek(fd, 0, SEEK_CUR);

	fstream = i_new(struct file_ostream, 1);
	ostream = o_stream_create_file_common(fstream, fd, 0, autoclose_fd);
	fstream_init_file(fstream);
	fstream->real_offset = offset;
	fstream->buffer_offset = offset;
	ostream->blocking = fstream->file;
	ostream->offset = offset;
	return ostream;
}

struct ostream *o_stream_create_fd_file_autoclose(int *fd, uoff_t offset)
{
	struct ostream *output;

	output = o_stream_create_fd_file(*fd, offset, TRUE);
	*fd = -1;
	return output;
}
