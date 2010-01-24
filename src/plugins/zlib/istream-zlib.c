/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#ifdef BZLIB_INCLUDE
#  define BUILD_SOURCE
#else
#  include "config.h"
#  undef HAVE_CONFIG_H
#  if _FILE_OFFSET_BITS == 64
#    define _LARGEFILE64_SOURCE
#  endif
#  include "lib.h"
#  include "istream-internal.h"
#  include "istream-zlib.h"
#  include <zlib.h>

#  ifdef HAVE_ZLIB
#    define BUILD_SOURCE
#    define HAVE_GZSEEK
#  endif
#endif

#ifdef BUILD_SOURCE
/* Default maximum buffer size. Seeking backwards is very expensive, so keep
   this pretty large */
#define DEFAULT_MAX_BUFFER_SIZE (1024*1024)

#include <unistd.h>

struct zlib_istream {
	struct istream_private istream;

	int fd;
	gzFile *file;
	uoff_t cached_size;
	uoff_t seek_offset;

	unsigned int marked:1;
};

static void i_stream_zlib_close(struct iostream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;

	if (zstream->file != NULL) {
		gzclose(zstream->file);
		zstream->file = NULL;
	}
}

static ssize_t i_stream_zlib_read(struct istream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;
	size_t size;
	const char *errstr;
	int ret, errnum;

	if (stream->pos == stream->buffer_size) {
		if (!zstream->marked && stream->skip > 0) {
			/* don't try to keep anything cached if we don't
			   have a seek mark. */
			i_stream_compress(stream);
		} else if (stream->max_buffer_size == 0 ||
			   stream->buffer_size < stream->max_buffer_size) {
			/* buffer is full - grow it */
			i_stream_grow_buffer(stream, I_STREAM_MIN_SIZE);
		}

		if (stream->pos == stream->buffer_size) {
			if (stream->skip > 0) {
				/* lose our buffer cache */
				i_stream_compress(stream);
			}

			if (stream->pos == stream->buffer_size)
				return -2; /* buffer full */
		}
	}

	size = stream->buffer_size - stream->pos;

	ret = -1;

	i_assert(zstream->seek_offset == stream->istream.v_offset +
		 (stream->pos - stream->skip));
	do {
	       ret = gzread(zstream->file, stream->w_buffer + stream->pos,
			    size);
	} while (ret < 0 && errno == EINTR && stream->istream.blocking);

	if (ret == 0) {
		/* EOF */
		stream->istream.eof = TRUE;
		return -1;
	}

	if (ret < 0) {
		errstr = gzerror(zstream->file, &errnum);
		if (errnum != Z_ERRNO) {
			i_error("gzread() failed: %s", errstr);
			stream->istream.stream_errno = EINVAL;
			return -1;
		}
		if (errno == EAGAIN) {
			i_assert(!stream->istream.blocking);
			ret = 0;
		} else {
			i_assert(errno != 0);
			stream->istream.stream_errno = errno;
			return -1;
		}
	}

	zstream->seek_offset += ret;
	stream->pos += ret;
	i_assert(ret > 0);
	return ret;
}

static void
i_stream_zlib_seek(struct istream_private *stream, uoff_t v_offset, bool mark)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;
	uoff_t start_offset = stream->istream.v_offset - stream->skip;

#ifndef HAVE_GZSEEK
	if (v_offset < start_offset) {
		/* need to reopen, but since closing the file closes the
		   file descriptor we'll have to duplicate it first. */
		int fd = dup(zstream->fd);
		if (fd == -1) {
			stream->istream.stream_errno = errno;
			i_error("zlib istream: dup() failed: %m");
			i_stream_close(&stream->istream);
			return;
		}
		gzclose(zstream->file);
		zstream->fd = fd;
		stream->fd = fd;
		zstream->file = gzdopen(zstream->fd, "r");
	}
#else
	if (v_offset < start_offset) {
		/* have to seek backwards */
		gzseek(zstream->file, v_offset, SEEK_SET);
		zstream->seek_offset = v_offset;

		stream->skip = stream->pos = 0;
		stream->istream.v_offset = v_offset;
	} else
#endif
	if (v_offset <= start_offset + stream->pos) {
		/* seeking backwards within what's already cached */
		stream->skip = v_offset - start_offset;
		stream->istream.v_offset = v_offset;
	} else {
		/* read and cache forward */
		do {
			size_t avail = stream->pos - stream->skip;
			if (stream->istream.v_offset + avail >= v_offset) {
				i_stream_skip(&stream->istream,
					      v_offset -
					      stream->istream.v_offset);
				break;
			}

			i_stream_skip(&stream->istream, avail);
		} while (i_stream_zlib_read(stream) >= 0);

		if (stream->istream.v_offset != v_offset) {
			/* some failure, we've broken it */
			if (stream->istream.stream_errno != 0) {
				i_error("zlib_istream.seek() failed: %s",
					strerror(stream->istream.stream_errno));
				i_stream_close(&stream->istream);
			} else {
				/* unexpected EOF. allow it since we may just
				   want to check if there's anything.. */
				i_assert(stream->istream.eof);
			}
		}
	}

	if (mark) {
		i_stream_compress(stream);
		zstream->marked = TRUE;
	}
}

static const struct stat *
i_stream_zlib_stat(struct istream_private *stream, bool exact)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;
	size_t size;

	if (fstat(zstream->fd, &stream->statbuf) < 0) {
		i_error("zlib_istream.fstat() failed: %m");
		return NULL;
	}

	if (!exact)
		return &stream->statbuf;

	if (zstream->cached_size == (uoff_t)-1) {
		uoff_t old_offset = stream->istream.v_offset;
		do {
			(void)i_stream_get_data(&stream->istream, &size);
			i_stream_skip(&stream->istream, size);
		} while (i_stream_zlib_read(stream) > 0);

		zstream->cached_size = stream->istream.v_offset;
		i_stream_seek(&stream->istream, old_offset);
	}
	stream->statbuf.st_size = zstream->cached_size;
	return &stream->statbuf;
}

static void i_stream_zlib_sync(struct istream_private *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;

	zstream->cached_size = (uoff_t)-1;
}

struct istream *i_stream_create_zlib(int fd)
{
	struct zlib_istream *zstream;
	struct stat st;

	zstream = i_new(struct zlib_istream, 1);
	zstream->fd = fd;
	zstream->file = gzdopen(fd, "r");
	zstream->cached_size = (uoff_t)-1;

	zstream->istream.iostream.close = i_stream_zlib_close;
	zstream->istream.max_buffer_size = DEFAULT_MAX_BUFFER_SIZE;
	zstream->istream.read = i_stream_zlib_read;
	zstream->istream.seek = i_stream_zlib_seek;
	zstream->istream.stat = i_stream_zlib_stat;
	zstream->istream.sync = i_stream_zlib_sync;

	/* if it's a file, set the flags properly */
	if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
		zstream->istream.istream.blocking = TRUE;
		zstream->istream.istream.seekable = TRUE;
	}

	zstream->istream.istream.readable_fd = FALSE;
	return i_stream_create(&zstream->istream, NULL, fd);
}
#endif
