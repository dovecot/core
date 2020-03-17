/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "ioloop.h"
#include "istream-file-private.h"
#include "net.h"

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

void i_stream_file_close(struct iostream_private *stream,
			 bool close_parent ATTR_UNUSED)
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
		io_stream_set_error(&stream->iostream,
				    "open(%s) failed: %m", path);
		stream->istream.stream_errno = errno;
		return -1;
	}
	return 0;
}

ssize_t i_stream_file_read(struct istream_private *stream)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	uoff_t offset;
	size_t size;
	ssize_t ret;

	if (!i_stream_try_alloc(stream, 1, &size))
		return -2;

	if (stream->fd == -1) {
		if (i_stream_file_open(stream) < 0)
			return -1;
		i_assert(stream->fd != -1);
	}

	offset = stream->istream.v_offset + (stream->pos - stream->skip);

	if (fstream->file) {
		ret = pread(stream->fd, stream->w_buffer + stream->pos,
			    size, offset);
	} else if (fstream->seen_eof) {
		/* don't try to read() again. EOF from keyboard (^D)
		   requires this to work right. */
		ret = 0;
	} else {
		ret = read(stream->fd, stream->w_buffer + stream->pos,
			   size);
	}

	if (ret == 0) {
		/* EOF */
		stream->istream.eof = TRUE;
		fstream->seen_eof = TRUE;
		return -1;
	}

	if (unlikely(ret < 0)) {
		if ((errno == EINTR || errno == EAGAIN) &&
		    !stream->istream.blocking) {
			ret = 0;
		} else {
			i_assert(errno != 0);
			/* if we get EBADF for a valid fd, it means something's
			   really wrong and we'd better just crash. */
			i_assert(errno != EBADF);
			if (fstream->file) {
				io_stream_set_error(&stream->iostream,
					"pread(size=%zu offset=%"PRIuUOFF_T") failed: %m",
					size, offset);
			} else {
				io_stream_set_error(&stream->iostream,
					"read(size=%zu) failed: %m",
					size);
			}
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
	stream->istream.eof = FALSE;
}

static int
i_stream_file_stat(struct istream_private *stream, bool exact ATTR_UNUSED)
{
	struct file_istream *fstream = (struct file_istream *) stream;
	const char *name = i_stream_get_name(&stream->istream);

	if (!fstream->file) {
		/* return defaults */
	} else if (stream->fd != -1) {
		if (fstat(stream->fd, &stream->statbuf) < 0) {
			stream->istream.stream_errno = errno;
			io_stream_set_error(&stream->iostream,
				"file_istream.fstat(%s) failed: %m", name);
			i_error("%s", i_stream_get_error(&stream->istream));
			return -1;
		}
	} else {
		if (stat(name, &stream->statbuf) < 0) {
			stream->istream.stream_errno = errno;
			io_stream_set_error(&stream->iostream,
				"file_istream.stat(%s) failed: %m", name);
			i_error("%s", i_stream_get_error(&stream->istream));
			return -1;
		}
	}
	return 0;
}

struct istream *
i_stream_create_file_common(struct file_istream *fstream,
			    int fd, const char *path,
			    size_t max_buffer_size, bool autoclose_fd)
{
	struct istream *input;
	struct stat st;
	bool is_file;
	int flags;

	fstream->autoclose_fd = autoclose_fd;

	fstream->istream.iostream.close = i_stream_file_close;
	fstream->istream.max_buffer_size = max_buffer_size;
	fstream->istream.read = i_stream_file_read;
	fstream->istream.seek = i_stream_file_seek;
	fstream->istream.sync = i_stream_file_sync;
	fstream->istream.stat = i_stream_file_stat;

	/* if it's a file, set the flags properly */
	if (fd == -1) {
		/* only the path is known for now - the fd is opened later */
		is_file = TRUE;
	} else if (fstat(fd, &st) < 0)
		is_file = FALSE;
	else if (S_ISREG(st.st_mode))
		is_file = TRUE;
	else if (!S_ISDIR(st.st_mode))
		is_file = FALSE;
	else {
		/* we're trying to open a directory.
		   we're not designed for it. */
		io_stream_set_error(&fstream->istream.iostream,
			"%s is a directory, can't read it as file",
			path != NULL ? path : t_strdup_printf("<fd %d>", fd));
		fstream->istream.istream.stream_errno = EISDIR;
		is_file = FALSE;
	}
	if (is_file) {
		fstream->file = TRUE;
		fstream->istream.istream.blocking = TRUE;
		fstream->istream.istream.seekable = TRUE;
	} else if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
		i_assert(fd > -1);
		/* shouldn't happen */
		fstream->istream.istream.stream_errno = errno;
		io_stream_set_error(&fstream->istream.iostream,
			"fcntl(%d, F_GETFL) failed: %m", fd);
	} else if ((flags & O_NONBLOCK) == 0) {
		/* blocking socket/fifo */
		fstream->istream.istream.blocking = TRUE;
	}
	fstream->istream.istream.readable_fd = TRUE;

	input = i_stream_create(&fstream->istream, NULL, fd, 0);
	i_stream_set_name(input, is_file ? "(file)" : "(fd)");
	return input;
}

struct istream *i_stream_create_fd(int fd, size_t max_buffer_size)
{
	struct file_istream *fstream;

	i_assert(fd != -1);

	fstream = i_new(struct file_istream, 1);
	return i_stream_create_file_common(fstream, fd, NULL,
					   max_buffer_size, FALSE);
}

struct istream *i_stream_create_fd_autoclose(int *fd, size_t max_buffer_size)
{
	struct istream *input;
	struct file_istream *fstream;

	i_assert(*fd != -1);

	fstream = i_new(struct file_istream, 1);
	input = i_stream_create_file_common(fstream, *fd, NULL,
					   max_buffer_size, TRUE);
	*fd = -1;
	return input;
}

struct istream *i_stream_create_file(const char *path, size_t max_buffer_size)
{
	struct file_istream *fstream;
	struct istream *input;

	fstream = i_new(struct file_istream, 1);
	input = i_stream_create_file_common(fstream, -1, path,
					    max_buffer_size, TRUE);
	i_stream_set_name(input, path);
	return input;
}
