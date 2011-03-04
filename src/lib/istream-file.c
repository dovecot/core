/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "ioloop.h"
#include "istream-internal.h"
#include "network.h"

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

struct file_istream {
	struct istream_private istream;

	uoff_t skip_left;

	unsigned int file:1;
	unsigned int autoclose_fd:1;
	unsigned int seen_eof:1;
};

static void i_stream_file_close(struct iostream_private *stream)
{
	struct file_istream *fstream = (struct file_istream *)stream;
	struct istream_private *_stream = (struct istream_private *)stream;

	if (fstream->autoclose_fd && _stream->fd != -1) {
		if (close(_stream->fd) < 0) {
			i_error("file_istream.close(%s) failed: %m",
				i_stream_get_name(&_stream->istream));
		}
	}
	_stream->fd = -1;
}

static int i_stream_file_open(struct istream_private *stream)
{
	const char *path = i_stream_get_name(&stream->istream);

	stream->fd = open(path, O_RDONLY);
	if (stream->fd == -1) {
		stream->istream.stream_errno = errno;
		i_error("file_istream.open(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

static ssize_t i_stream_file_read(struct istream_private *stream)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	size_t size;
	ssize_t ret;

	if (!i_stream_get_buffer_space(stream, 1, &size))
		return -2;

	if (stream->fd == -1) {
		if (i_stream_file_open(stream) < 0)
			return -1;
	}

	do {
		if (fstream->file) {
			ret = pread(stream->fd, stream->w_buffer + stream->pos,
				    size, stream->istream.v_offset +
				    (stream->pos - stream->skip));
		} else if (fstream->seen_eof) {
			/* don't try to read() again. EOF from keyboard (^D)
			   requires this to work right. */
			ret = 0;
		} else {
			ret = read(stream->fd, stream->w_buffer + stream->pos,
				   size);
		}
	} while (unlikely(ret < 0 && errno == EINTR &&
			  stream->istream.blocking));

	if (ret == 0) {
		/* EOF */
		stream->istream.eof = TRUE;
		fstream->seen_eof = TRUE;
		return -1;
	}

	if (unlikely(ret < 0)) {
		if (errno == EINTR || errno == EAGAIN) {
			i_assert(!stream->istream.blocking);
			ret = 0;
		} else {
			i_assert(errno != 0);
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
	i_assert(ret != -1);
	return ret;
}

static void i_stream_file_seek(struct istream_private *stream, uoff_t v_offset,
			       bool mark ATTR_UNUSED)
{
	struct file_istream *fstream = (struct file_istream *) stream;

	if (!stream->istream.seekable) {
		if (v_offset < stream->istream.v_offset)
			i_panic("stream doesn't support seeking backwards");
		fstream->skip_left += v_offset - stream->istream.v_offset;
	}

	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
	fstream->seen_eof = FALSE;
}

static void i_stream_file_sync(struct istream_private *stream)
{
	if (!stream->istream.seekable) {
		/* can't do anything or data would be lost */
		return;
	}

	stream->skip = stream->pos = 0;
}

static const struct stat *
i_stream_file_stat(struct istream_private *stream, bool exact ATTR_UNUSED)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	const char *name = i_stream_get_name(&stream->istream);

	if (!fstream->file) {
		/* return defaults */
	} else if (stream->fd != -1) {
		if (fstat(stream->fd, &stream->statbuf) < 0) {
			i_error("file_istream.fstat(%s) failed: %m", name);
			return NULL;
		}
	} else {
		if (stat(name, &stream->statbuf) < 0) {
			i_error("file_istream.stat(%s) failed: %m", name);
			return NULL;
		}
	}

	return &stream->statbuf;
}

static struct istream *
i_stream_create_file_common(int fd, size_t max_buffer_size, bool autoclose_fd)
{
	struct file_istream *fstream;
	struct stat st;
	bool is_file;

	fstream = i_new(struct file_istream, 1);
	fstream->autoclose_fd = autoclose_fd;

	fstream->istream.iostream.close = i_stream_file_close;
	fstream->istream.max_buffer_size = max_buffer_size;
	fstream->istream.read = i_stream_file_read;
	fstream->istream.seek = i_stream_file_seek;
	fstream->istream.sync = i_stream_file_sync;
	fstream->istream.stat = i_stream_file_stat;

	/* if it's a file, set the flags properly */
	if (fd == -1)
		is_file = TRUE;
	else if (fstat(fd, &st) < 0)
		is_file = FALSE;
	else if (S_ISREG(st.st_mode))
		is_file = TRUE;
	else if (!S_ISDIR(st.st_mode))
		is_file = FALSE;
	else {
		/* we're trying to open a directory.
		   we're not designed for it. */
		fstream->istream.istream.stream_errno = EISDIR;
		is_file = FALSE;
	}
	if (is_file) {
		fstream->file = TRUE;
		fstream->istream.istream.blocking = TRUE;
		fstream->istream.istream.seekable = TRUE;
	}
	fstream->istream.istream.readable_fd = TRUE;

	return i_stream_create(&fstream->istream, NULL, fd);
}

struct istream *i_stream_create_fd(int fd, size_t max_buffer_size,
				   bool autoclose_fd)
{
	i_assert(fd != -1);

	return i_stream_create_file_common(fd, max_buffer_size, autoclose_fd);
}

struct istream *i_stream_create_file(const char *path, size_t max_buffer_size)
{
	struct istream *input;

	input = i_stream_create_file_common(-1, max_buffer_size, TRUE);
	i_stream_set_name(input, path);
	return input;
}
