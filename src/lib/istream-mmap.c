/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mmap-util.h"
#include "istream-internal.h"

#include <unistd.h>
#include <sys/stat.h>

struct mmap_istream {
	struct istream_private istream;

        struct timeval fstat_cache_stamp;

	void *mmap_base;
	off_t mmap_offset;
	uoff_t v_size;

	unsigned int autoclose_fd:1;
};

static size_t mmap_pagemask = 0;

static void i_stream_mmap_close(struct iostream_private *stream)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;

	if (mstream->autoclose_fd && mstream->istream.fd != -1) {
		if (close(mstream->istream.fd) < 0) {
			i_error("mmap_istream.close(%s) failed: %m",
				i_stream_get_name(&mstream->istream.istream));
		}
	}
	mstream->istream.fd = -1;
}

static void i_stream_munmap(struct mmap_istream *mstream)
{
	struct istream_private *_stream = &mstream->istream;

	if (_stream->buffer != NULL) {
		if (munmap(mstream->mmap_base, _stream->buffer_size) < 0) {
			i_error("mmap_istream.munmap(%s) failed: %m",
				i_stream_get_name(&_stream->istream));
		}
		mstream->mmap_base = NULL;
		_stream->buffer = NULL;
		_stream->buffer_size = 0;
		mstream->mmap_offset = 0;
	}
}

static void i_stream_mmap_destroy(struct iostream_private *stream)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;

	i_stream_munmap(mstream);
}

static size_t mstream_get_mmap_block_size(struct istream_private *stream)
{
	return (stream->max_buffer_size + mmap_get_page_size() - 1) & ~
		(mmap_get_page_size() - 1);
}

static ssize_t i_stream_mmap_read(struct istream_private *stream)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;
	size_t aligned_skip;
	uoff_t top;

	if (stream->pos < stream->buffer_size) {
		/* more bytes available without needing to mmap() */
		stream->pos = stream->buffer_size;
		return stream->pos - stream->skip;
	}

	if (stream->istream.v_offset >= mstream->v_size) {
		stream->istream.eof = TRUE;
		return -1;
	}

	aligned_skip = stream->skip & ~mmap_pagemask;
	if (aligned_skip == 0 && mstream->mmap_base != NULL) {
		/* didn't skip enough bytes */
		return -2;
	}

	stream->skip -= aligned_skip;
	mstream->mmap_offset += aligned_skip;

	if (mstream->mmap_base != NULL) {
		if (munmap(mstream->mmap_base, stream->buffer_size) < 0) {
			i_error("mmap_istream.munmap(%s) failed: %m",
				i_stream_get_name(&stream->istream));
		}
	}

	top = mstream->v_size - mstream->mmap_offset;
	stream->buffer_size = I_MIN(top, mstream_get_mmap_block_size(stream));

	i_assert((uoff_t)mstream->mmap_offset + stream->buffer_size <=
		 mstream->v_size);

	if (stream->buffer_size == 0) {
		/* don't bother even trying mmap */
		mstream->mmap_base = NULL;
		stream->buffer = NULL;
	} else {
		mstream->mmap_base =
			mmap(NULL, stream->buffer_size, PROT_READ, MAP_PRIVATE,
			     stream->fd, mstream->mmap_offset);
		if (mstream->mmap_base == MAP_FAILED) {
			i_assert(errno != 0);
			stream->istream.stream_errno = errno;
			mstream->mmap_base = NULL;
			stream->buffer = NULL;
			stream->buffer_size = 0;
			stream->skip = stream->pos = 0;
			i_error("mmap_istream.mmap(%s) failed: %m",
				i_stream_get_name(&stream->istream));
			return -1;
		}
		stream->buffer = mstream->mmap_base;
	}

	if (stream->buffer_size > mmap_get_page_size()) {
		if (madvise(mstream->mmap_base, stream->buffer_size,
			    MADV_SEQUENTIAL) < 0) {
			i_error("mmap_istream.madvise(%s): %m",
				i_stream_get_name(&stream->istream));
		}
	}

	stream->pos = stream->buffer_size;
	i_assert(stream->pos - stream->skip > 0);
	return stream->pos - stream->skip;
}

static void i_stream_mmap_seek(struct istream_private *stream, uoff_t v_offset,
			       bool mark ATTR_UNUSED)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;

	if (stream->buffer_size != 0 &&
	    (uoff_t)mstream->mmap_offset <= v_offset &&
	    (uoff_t)mstream->mmap_offset + stream->buffer_size > v_offset) {
		/* already mmaped */
		stream->skip = stream->pos = v_offset - mstream->mmap_offset;
	} else {
		/* force reading next time */
		i_stream_munmap(mstream);
		stream->skip = stream->pos = v_offset;
	}

	stream->istream.v_offset = v_offset;
}

static void i_stream_mmap_sync(struct istream_private *stream)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;

	i_stream_munmap(mstream);
	stream->skip = stream->pos = stream->istream.v_offset;

	mstream->fstat_cache_stamp.tv_sec = 0;
}

static int fstat_cached(struct mmap_istream *mstream)
{
	if (mstream->fstat_cache_stamp.tv_sec == ioloop_timeval.tv_sec &&
	    mstream->fstat_cache_stamp.tv_usec == ioloop_timeval.tv_usec)
		return 0;

	if (fstat(mstream->istream.fd, &mstream->istream.statbuf) < 0) {
		i_error("mmap_istream.fstat(%s) failed: %m",
			i_stream_get_name(&mstream->istream.istream));
		return -1;
	}

	mstream->fstat_cache_stamp = ioloop_timeval;
	return 0;
}

static const struct stat *
i_stream_mmap_stat(struct istream_private *stream, bool exact ATTR_UNUSED)
{
	struct mmap_istream *mstream = (struct mmap_istream *) stream;

	if (fstat_cached(mstream) < 0)
		return NULL;

	return &stream->statbuf;
}

struct istream *i_stream_create_mmap(int fd, size_t block_size,
				     uoff_t start_offset, uoff_t v_size,
				     bool autoclose_fd)
{
	struct mmap_istream *mstream;
        struct istream *istream;
	struct stat st;

	if (mmap_pagemask == 0)
		mmap_pagemask = mmap_get_page_size()-1;

	if (v_size == 0) {
		if (fstat(fd, &st) < 0)
			i_error("i_stream_create_mmap(): fstat() failed: %m");
		else {
			v_size = st.st_size;
			if (start_offset > v_size)
				start_offset = v_size;
			v_size -= start_offset;
		}
	}

	mstream = i_new(struct mmap_istream, 1);
	mstream->autoclose_fd = autoclose_fd;
	mstream->v_size = v_size;

	mstream->istream.iostream.close = i_stream_mmap_close;
	mstream->istream.iostream.destroy = i_stream_mmap_destroy;

	mstream->istream.max_buffer_size = block_size;
	mstream->istream.read = i_stream_mmap_read;
	mstream->istream.seek = i_stream_mmap_seek;
	mstream->istream.sync = i_stream_mmap_sync;
	mstream->istream.stat = i_stream_mmap_stat;

	mstream->istream.istream.readable_fd = TRUE;
	mstream->istream.abs_start_offset = start_offset;
	istream = i_stream_create(&mstream->istream, NULL, fd);
	istream->mmaped = TRUE;
	istream->blocking = TRUE;
	istream->seekable = TRUE;
	return istream;
}
