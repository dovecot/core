/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "istream-internal.h"

#include <unistd.h>
#include <sys/stat.h>

struct mmap_istream {
	struct _istream istream;

	int fd;
	void *mmap_base;
	off_t mmap_offset;
	size_t mmap_block_size;

	unsigned int autoclose_fd:1;
};

static size_t mmap_pagesize = 0;
static size_t mmap_pagemask = 0;

static void _close(struct _iostream *stream)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;

	if (mstream->autoclose_fd && mstream->fd != -1) {
		if (close(mstream->fd) < 0)
			i_error("mmap_istream.close() failed: %m");
		mstream->fd = -1;
	}
}

static void i_stream_munmap(struct mmap_istream *mstream)
{
	struct _istream *_stream = &mstream->istream;

	if (_stream->buffer != NULL) {
		if (munmap(mstream->mmap_base, _stream->buffer_size) < 0)
			i_error("mmap_istream.munmap() failed: %m");
		mstream->mmap_base = NULL;
		_stream->buffer = NULL;
		_stream->buffer_size = 0;
		mstream->mmap_offset = 0;
	}
}

static void _destroy(struct _iostream *stream)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;

	i_stream_munmap(mstream);
}

static void _set_max_buffer_size(struct _iostream *stream, size_t max_size)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;

	/* allow only full page sizes */
	if (max_size < mmap_pagesize)
		mstream->mmap_block_size = mmap_pagesize;
	else {
		if (max_size % mmap_pagesize != 0)
			max_size += mmap_pagesize - (max_size % mmap_pagesize);
		mstream->mmap_block_size = max_size;
	}
}

static void _set_blocking(struct _iostream *stream __attr_unused__,
			  int timeout_msecs __attr_unused__,
			  void (*timeout_cb)(void *) __attr_unused__,
			  void *context __attr_unused__)
{
	/* we never block */
}

static ssize_t io_stream_set_mmaped_pos(struct _istream *stream)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;
	uoff_t top;

	i_assert((uoff_t)mstream->mmap_offset <=
		 stream->istream.start_offset + stream->istream.v_limit);

	top = stream->istream.start_offset + stream->istream.v_limit -
		mstream->mmap_offset;
	stream->pos = I_MIN(top, stream->buffer_size);

	return stream->pos - stream->skip;
}

static ssize_t _read(struct _istream *stream)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;
	size_t aligned_skip, limit_size;
	uoff_t top;

	if (stream->istream.start_offset + stream->istream.v_limit <=
	    (uoff_t)mstream->mmap_offset + stream->pos) {
		/* end of file */
		stream->istream.stream_errno = 0;
		return -1;
	}

	if (stream->pos < stream->buffer_size) {
		/* more bytes available without needing to mmap() */
		return io_stream_set_mmaped_pos(stream);
	}

	aligned_skip = stream->skip & ~mmap_pagemask;
	if (aligned_skip == 0 && mstream->mmap_base != NULL) {
		/* didn't skip enough bytes */
		return -2;
	}

	stream->skip -= aligned_skip;
	mstream->mmap_offset += aligned_skip;

	if (mstream->mmap_base != NULL) {
		if (munmap(mstream->mmap_base, stream->buffer_size) < 0)
			i_error("io_stream_read_mmaped(): munmap() failed: %m");
	}

	top = stream->istream.start_offset + stream->istream.v_size -
		mstream->mmap_offset;
	stream->buffer_size = I_MIN(top, mstream->mmap_block_size);

	i_assert((uoff_t)mstream->mmap_offset + stream->buffer_size <=
		 stream->istream.start_offset + stream->istream.v_size);

	mstream->mmap_base = mmap(NULL, stream->buffer_size,
				  PROT_READ, MAP_PRIVATE,
				  mstream->fd, mstream->mmap_offset);
	if (mstream->mmap_base == MAP_FAILED) {
		stream->istream.stream_errno = errno;
		mstream->mmap_base = NULL;
		stream->buffer = NULL;
		stream->buffer_size = 0;
		stream->skip = stream->pos = 0;
		i_error("mmap_istream.mmap() failed: %m");
		return -1;
	}
	stream->buffer = mstream->mmap_base;

	/* madvise() only if non-limited mmap()ed buffer area larger than
	   page size */
	limit_size = stream->istream.start_offset + stream->istream.v_limit -
		mstream->mmap_offset;
	if (limit_size > mmap_pagesize) {
		if (limit_size > stream->buffer_size)
			limit_size = stream->buffer_size;

		if (madvise(mstream->mmap_base, limit_size,
			    MADV_SEQUENTIAL) < 0)
			i_error("mmap_istream.madvise(): %m");
	}

	return io_stream_set_mmaped_pos(stream);
}

static void _seek(struct _istream *stream, uoff_t v_offset)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;
	uoff_t abs_offset;

	abs_offset = stream->istream.start_offset + v_offset;
	if (stream->buffer_size != 0 &&
	    (uoff_t)mstream->mmap_offset <= abs_offset &&
	    (uoff_t)mstream->mmap_offset + stream->buffer_size > abs_offset) {
		/* already mmaped */
		stream->skip = stream->pos = abs_offset - mstream->mmap_offset;
	} else {
		/* force reading next time */
		i_stream_munmap(mstream);
		stream->skip = stream->pos = abs_offset;
	}

	stream->istream.v_offset = v_offset;
}

static void _skip(struct _istream *stream, uoff_t count)
{
	_seek(stream, stream->istream.v_offset + count);
}

struct istream *i_stream_create_mmap(int fd, pool_t pool, size_t block_size,
				     uoff_t start_offset, uoff_t v_size,
				     int autoclose_fd)
{
	struct mmap_istream *mstream;
        struct istream *istream;
	struct stat st;

	if (mmap_pagesize == 0) {
		mmap_pagesize = getpagesize();
		mmap_pagemask = mmap_pagesize-1;
	}

	if (v_size == 0) {
		if (fstat(fd, &st) < 0) {
			i_error("i_stream_create_mmap(): fstat() failed: %m");
			v_size = 0;
		} else {
			v_size = st.st_size;
			if (start_offset > v_size)
				start_offset = v_size;
			v_size -= start_offset;
		}
	}

	mstream = p_new(pool, struct mmap_istream, 1);
	mstream->fd = fd;
        _set_max_buffer_size(&mstream->istream.iostream, block_size);
	mstream->autoclose_fd = autoclose_fd;

	mstream->istream.iostream.close = _close;
	mstream->istream.iostream.destroy = _destroy;
	mstream->istream.iostream.set_max_buffer_size = _set_max_buffer_size;
	mstream->istream.iostream.set_blocking = _set_blocking;

	mstream->istream.read = _read;
	mstream->istream.skip_count = _skip;
	mstream->istream.seek = _seek;

	istream = _i_stream_create(&mstream->istream, pool, fd,
				   start_offset, v_size);
	istream->mmaped = TRUE;
	return istream;
}
