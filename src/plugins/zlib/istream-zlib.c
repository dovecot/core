/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "istream-internal.h"
#include "istream-zlib.h"

#include <zlib.h>

/* Default maximum buffer size. Seeking backwards is very expensive, so keep
   this pretty large */
#define DEFAULT_MAX_BUFFER_SIZE (1024*1024)

#define I_STREAM_MIN_SIZE 4096

struct zlib_istream {
	struct _istream istream;

	int fd;
	gzFile *file;
	uoff_t cached_size;
	uoff_t seek_offset;

	unsigned int marked:1;
};

static void _close(struct _iostream *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;

	if (zstream->file != NULL) {
		gzclose(zstream->file);
		zstream->file = NULL;
	}
}

static void _destroy(struct _iostream *stream __attr_unused__)
{
	struct _istream *_stream = (struct _istream *) stream;

	p_free(_stream->iostream.pool, _stream->w_buffer);
}

static void i_stream_compress(struct _istream *stream)
{
	memmove(stream->w_buffer, stream->w_buffer + stream->skip,
		stream->pos - stream->skip);
	stream->pos -= stream->skip;

	stream->skip = 0;
}

static ssize_t _read(struct _istream *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *)stream;
	size_t size;
	int ret;

	if (stream->istream.closed)
		return -1;

	stream->istream.stream_errno = 0;

	if (stream->pos == stream->buffer_size) {
		if (!zstream->marked && stream->skip > 0) {
			/* don't try to keep anything cached if we don't
			   have a seek mark. */
			i_stream_compress(stream);
		}

		if (stream->max_buffer_size == 0 ||
		    stream->buffer_size < stream->max_buffer_size) {
			/* buffer is full - grow it */
			_i_stream_grow_buffer(stream, I_STREAM_MIN_SIZE);
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
		if (errno == EAGAIN) {
			i_assert(!stream->istream.blocking);
			ret = 0;
		} else {
			stream->istream.eof = TRUE;
			stream->istream.stream_errno = errno;
			return -1;
		}
	}

	zstream->seek_offset += ret;
	stream->pos += ret;
	i_assert(ret != 0);
	return ret;
}

static void _seek(struct _istream *stream, uoff_t v_offset, bool mark)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;
	uoff_t start_offset = stream->istream.v_offset - stream->skip;

	stream->istream.stream_errno = 0;

	if (v_offset < start_offset) {
		/* have to seek backwards */
		gzseek(zstream->file, v_offset, SEEK_SET);
		zstream->seek_offset = v_offset;

		stream->skip = stream->pos = 0;
		stream->istream.v_offset = v_offset;
	} else if (v_offset <= start_offset + stream->pos) {
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
		} while (_read(stream) >= 0);

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

static const struct stat *_stat(struct _istream *stream, bool exact)
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
		} while (_read(stream) > 0);

		zstream->cached_size = stream->istream.v_offset;
		i_stream_seek(&stream->istream, old_offset);
	}
	stream->statbuf.st_size = zstream->cached_size;
	return &stream->statbuf;
}

static void _sync(struct _istream *stream)
{
	struct zlib_istream *zstream = (struct zlib_istream *) stream;

	zstream->cached_size = (uoff_t)-1;
}

struct istream *i_stream_create_zlib(int fd, pool_t pool)
{
	struct zlib_istream *zstream;
	struct stat st;

	zstream = p_new(pool, struct zlib_istream, 1);
	zstream->fd = fd;
	zstream->file = gzdopen(fd, "r");
	zstream->cached_size = (uoff_t)-1;

	zstream->istream.iostream.close = _close;
	zstream->istream.iostream.destroy = _destroy;

	zstream->istream.max_buffer_size = DEFAULT_MAX_BUFFER_SIZE;
	zstream->istream.read = _read;
	zstream->istream.seek = _seek;
	zstream->istream.stat = _stat;
	zstream->istream.sync = _sync;

	/* if it's a file, set the flags properly */
	if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
		zstream->istream.istream.blocking = TRUE;
		zstream->istream.istream.seekable = TRUE;
	}

	return _i_stream_create(&zstream->istream, pool, fd, 0);
}
