/*
   ibuffer-mmap.c : Input buffer handling for mmap()ed files

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
#include "mmap-util.h"
#include "ibuffer-internal.h"

#include <unistd.h>
#include <sys/stat.h>

typedef struct {
	_IBuffer ibuf;

	int fd;
	void *mmap_base;
	uoff_t mmap_offset;
	size_t mmap_block_size;

	unsigned int autoclose_fd:1;
} MmapIBuffer;

static size_t mmap_pagesize = 0;
static size_t mmap_pagemask = 0;

static void _close(_IOBuffer *buf)
{
	MmapIBuffer *mbuf = (MmapIBuffer *) buf;

	if (mbuf->autoclose_fd && mbuf->fd != -1) {
		if (close(mbuf->fd) < 0)
			i_error("MmapIBuffer.close() failed: %m");
		mbuf->fd = -1;
	}
}

static void i_buffer_munmap(MmapIBuffer *mbuf)
{
	_IBuffer *_buf = &mbuf->ibuf;

	if (_buf->buffer != NULL) {
		if (munmap(mbuf->mmap_base, _buf->buffer_size) < 0)
			i_error("MmapIBuffer.munmap() failed: %m");
		mbuf->mmap_base = NULL;
		_buf->buffer = NULL;
		_buf->buffer_size = 0;
		mbuf->mmap_offset = 0;
	}
}

static void _destroy(_IOBuffer *buf)
{
	MmapIBuffer *mbuf = (MmapIBuffer *) buf;

	i_buffer_munmap(mbuf);
}

static void _set_max_size(_IOBuffer *buf, size_t max_size)
{
	MmapIBuffer *mbuf = (MmapIBuffer *) buf;

	mbuf->mmap_block_size = max_size;
}

static void _set_blocking(_IOBuffer *buf __attr_unused__,
			  int timeout_msecs __attr_unused__,
			  TimeoutFunc timeout_func __attr_unused__,
			  void *context __attr_unused__)
{
	/* we never block */
}

static ssize_t io_buffer_set_mmaped_pos(_IBuffer *buf)
{
	MmapIBuffer *mbuf = (MmapIBuffer *) buf;

	i_assert((uoff_t)mbuf->mmap_offset <=
		 buf->ibuffer.start_offset + buf->ibuffer.v_limit);

	buf->pos = buf->ibuffer.start_offset + buf->ibuffer.v_limit -
		mbuf->mmap_offset;
	if (buf->pos > buf->buffer_size)
		buf->pos = buf->buffer_size;

	return buf->pos - buf->skip;
}

static ssize_t _read(_IBuffer *buf)
{
	MmapIBuffer *mbuf = (MmapIBuffer *) buf;
	size_t aligned_skip, limit_size;

	if (buf->ibuffer.start_offset + buf->ibuffer.v_limit <=
	    (uoff_t)mbuf->mmap_offset + buf->pos) {
		/* end of file */
		return -1;
	}

	if (buf->pos < buf->buffer_size) {
		/* more bytes available without needing to mmap() */
		return io_buffer_set_mmaped_pos(buf);
	}

	aligned_skip = buf->skip & ~mmap_pagemask;
	if (aligned_skip == 0 && mbuf->mmap_base != NULL) {
		/* didn't skip enough bytes */
		return -2;
	}

	buf->skip -= aligned_skip;
	mbuf->mmap_offset += aligned_skip;

	if (mbuf->mmap_base != NULL) {
		if (munmap(mbuf->mmap_base, buf->buffer_size) < 0)
			i_error("io_buffer_read_mmaped(): munmap() failed: %m");
	}

	buf->buffer_size = buf->ibuffer.start_offset + buf->ibuffer.v_size -
		mbuf->mmap_offset;
	if (buf->buffer_size > mbuf->mmap_block_size)
		buf->buffer_size = mbuf->mmap_block_size;

	i_assert((uoff_t)mbuf->mmap_offset + buf->buffer_size <=
		 buf->ibuffer.start_offset + buf->ibuffer.v_size);

	mbuf->mmap_base = mmap(NULL, buf->buffer_size, PROT_READ, MAP_PRIVATE,
			       mbuf->fd, mbuf->mmap_offset);
	buf->buffer = mbuf->mmap_base;
	if (mbuf->mmap_base == MAP_FAILED) {
		buf->ibuffer.buf_errno = errno;
		mbuf->mmap_base = NULL;
		buf->buffer = NULL;
		buf->buffer_size = 0;
		buf->skip = buf->pos = 0;
		i_error("MmapIBuffer.mmap() failed: %m");
		return -1;
	}

	/* madvise() only if non-limited mmap()ed buffer area larger than
	   page size */
	limit_size = buf->ibuffer.start_offset + buf->ibuffer.v_limit -
		mbuf->mmap_offset;
	if (limit_size > mmap_pagesize) {
		if (limit_size > buf->buffer_size)
			limit_size = buf->buffer_size;

		(void)madvise(mbuf->mmap_base, limit_size, MADV_SEQUENTIAL);
	}

	return io_buffer_set_mmaped_pos(buf);
}

static int _seek(_IBuffer *buf, uoff_t v_offset)
{
	MmapIBuffer *mbuf = (MmapIBuffer *) buf;
	uoff_t abs_offset;

	abs_offset = buf->ibuffer.start_offset + v_offset;
	if (buf->buffer_size != 0 &&
	    mbuf->mmap_offset <= abs_offset &&
	    mbuf->mmap_offset + buf->buffer_size > abs_offset) {
		/* already mmaped */
		buf->skip = buf->pos = abs_offset - mbuf->mmap_offset;
	} else {
		/* force reading next time */
		i_buffer_munmap(mbuf);
		buf->skip = buf->pos = abs_offset;
	}

	buf->ibuffer.v_offset = v_offset;
	return 1;
}

static void _skip(_IBuffer *buf, uoff_t count)
{
	_seek(buf, buf->ibuffer.v_offset + count);
}

IBuffer *i_buffer_create_mmap(int fd, Pool pool, size_t block_size,
			      uoff_t start_offset, uoff_t v_size,
			      int autoclose_fd)
{
	MmapIBuffer *mbuf;
	struct stat st;

	if (mmap_pagesize == 0) {
		mmap_pagesize = getpagesize();
		mmap_pagemask = mmap_pagesize-1;
	}

	if (v_size == 0) {
		if (fstat(fd, &st) < 0) {
			i_error("i_buffer_create_mmap(): fstat() failed: %m");
			v_size = 0;
		} else {
			v_size = st.st_size;
			if (start_offset > v_size)
				start_offset = v_size;
			v_size -= start_offset;
		}
	}

	mbuf = p_new(pool, MmapIBuffer, 1);
	mbuf->fd = fd;
	mbuf->mmap_block_size = block_size;
	mbuf->autoclose_fd = autoclose_fd;

	mbuf->ibuf.iobuf.close = _close;
	mbuf->ibuf.iobuf.destroy = _destroy;
	mbuf->ibuf.iobuf.set_max_size = _set_max_size;
	mbuf->ibuf.iobuf.set_blocking = _set_blocking;

	mbuf->ibuf.read = _read;
	mbuf->ibuf.skip_count = _skip;
	mbuf->ibuf.seek = _seek;

	return _i_buffer_create(&mbuf->ibuf, pool, fd, start_offset, v_size);
}
