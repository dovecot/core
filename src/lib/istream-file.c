/* Copyright (c) 2002-2003 Timo Sirainen */

/* @UNSAFE: whole file */

#include "lib.h"
#include "ioloop.h"
#include "istream-internal.h"
#include "network.h"

#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

struct file_istream {
	struct _istream istream;

	uoff_t skip_left;

	unsigned int file:1;
	unsigned int autoclose_fd:1;
};

static void _close(struct _iostream *stream)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	struct _istream *_stream = (struct _istream *) stream;

	if (fstream->autoclose_fd && _stream->fd != -1) {
		if (close(_stream->fd) < 0)
			i_error("file_istream.close() failed: %m");
	}
	_stream->fd = -1;
}

static void _destroy(struct _iostream *stream)
{
	struct _istream *_stream = (struct _istream *) stream;

	i_free(_stream->w_buffer);
}

static ssize_t _read(struct _istream *stream)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	size_t size;
	ssize_t ret;

	if (stream->istream.closed)
		return -1;

	stream->istream.stream_errno = 0;

	if (stream->pos == stream->buffer_size) {
		if (stream->skip > 0) {
			/* remove the unused bytes from beginning of buffer */
                        _i_stream_compress(stream);
		} else if (stream->max_buffer_size == 0 ||
			   stream->buffer_size < stream->max_buffer_size) {
			/* buffer is full - grow it */
			_i_stream_grow_buffer(stream, I_STREAM_MIN_SIZE);
		}

		if (stream->pos == stream->buffer_size)
			return -2; /* buffer full */
	}

	size = stream->buffer_size - stream->pos;

	ret = -1;

	do {
		if (fstream->file) {
			ret = pread(stream->fd, stream->w_buffer + stream->pos,
				    size, stream->istream.v_offset +
				    (stream->pos - stream->skip));
		} else {
			ret = read(stream->fd, stream->w_buffer + stream->pos,
				   size);
		}
	} while (ret < 0 && errno == EINTR && stream->istream.blocking);

	if (ret == 0) {
		/* EOF */
		stream->istream.eof = TRUE;
		return -1;
	}

	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN) {
			i_assert(!stream->istream.blocking);
			ret = 0;
		} else {
			stream->istream.eof = TRUE;
			stream->istream.stream_errno = errno;
			return -1;
		}
	}

	if (ret > 0 && fstream->skip_left > 0) {
		i_assert(!fstream->file);
		i_assert(stream->skip == stream->pos);

		if (fstream->skip_left >= (size_t)ret) {
			fstream->skip_left -= ret;
			ret = 0;
		} else {
			ret -= fstream->skip_left;
			stream->pos += fstream->skip_left;
			stream->skip += fstream->skip_left;
			fstream->skip_left = 0;
		}
	}

	stream->pos += ret;
	i_assert(ret != 0 || !fstream->file);
	return ret;
}

static void _seek(struct _istream *stream, uoff_t v_offset,
		  bool mark __attr_unused__)
{
	struct file_istream *fstream = (struct file_istream *) stream;

	if (!stream->istream.seekable) {
		if (v_offset < stream->istream.v_offset) {
			stream->istream.stream_errno = ESPIPE;
			return;
		}
		fstream->skip_left += v_offset - stream->istream.v_offset;
	}

	stream->istream.stream_errno = 0;
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
}

static void _sync(struct _istream *stream)
{
	if (!stream->istream.seekable) {
		/* can't do anything or data would be lost */
		return;
	}

	stream->skip = stream->pos = 0;
}

static const struct stat *
_stat(struct _istream *stream, bool exact __attr_unused__)
{
	struct file_istream *fstream = (struct file_istream *) stream;

	if (fstream->file) {
		if (fstat(fstream->istream.fd, &fstream->istream.statbuf) < 0) {
			i_error("file_istream.fstat() failed: %m");
			return NULL;
		}
	}

	return &stream->statbuf;
}

struct istream *i_stream_create_fd(int fd, size_t max_buffer_size,
				   bool autoclose_fd)
{
	struct file_istream *fstream;
	struct stat st;

	fstream = i_new(struct file_istream, 1);
	fstream->autoclose_fd = autoclose_fd;

	fstream->istream.iostream.close = _close;
	fstream->istream.iostream.destroy = _destroy;

	fstream->istream.max_buffer_size = max_buffer_size;
	fstream->istream.read = _read;
	fstream->istream.seek = _seek;
	fstream->istream.sync = _sync;
	fstream->istream.stat = _stat;

	/* if it's a file, set the flags properly */
	if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
		fstream->file = TRUE;
		fstream->istream.istream.blocking = TRUE;
		fstream->istream.istream.seekable = TRUE;
	}

	return _i_stream_create(&fstream->istream, fd, 0);
}
