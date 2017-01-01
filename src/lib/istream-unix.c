/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fdpass.h"
#include "istream-file-private.h"
#include "istream-unix.h"

struct unix_istream {
	struct file_istream fstream;
	bool next_read_fd;
	int read_fd;
};

static void
i_stream_unix_close(struct iostream_private *stream, bool close_parent)
{
	struct unix_istream *ustream = (struct unix_istream *)stream;

	if (ustream->read_fd != -1)
		i_close_fd(&ustream->read_fd);
	i_stream_file_close(stream, close_parent);
}

static ssize_t i_stream_unix_read(struct istream_private *stream)
{
	struct unix_istream *ustream = (struct unix_istream *)stream;
	size_t size;
	ssize_t ret;

	if (!ustream->next_read_fd)
		return i_stream_file_read(stream);

	i_assert(ustream->read_fd == -1);
	i_assert(ustream->fstream.skip_left == 0); /* not supported here.. */
	if (!i_stream_try_alloc(stream, 1, &size))
		return -2;

	do {
		ret = fd_read(stream->fd,
			      stream->w_buffer + stream->pos, size,
			      &ustream->read_fd);
	} while (unlikely(ret < 0 && errno == EINTR &&
			  stream->istream.blocking));
	if (ustream->read_fd != -1)
		ustream->next_read_fd = FALSE;

	if (ret == 0) {
		/* EOF */
		stream->istream.eof = TRUE;
		ustream->fstream.seen_eof = TRUE;
		return -1;
	}

	if (unlikely(ret < 0)) {
		if (errno == EINTR || errno == EAGAIN) {
			i_assert(!stream->istream.blocking);
			return 0;
		} else {
			i_assert(errno != 0);
			/* if we get EBADF for a valid fd, it means something's
			   really wrong and we'd better just crash. */
			i_assert(errno != EBADF);
			stream->istream.stream_errno = errno;
			return -1;
		}
	}
	stream->pos += ret;
	return ret;
}

struct istream *i_stream_create_unix(int fd, size_t max_buffer_size)
{
	struct unix_istream *ustream;
	struct istream *input;

	i_assert(fd != -1);

	ustream = i_new(struct unix_istream, 1);
	ustream->read_fd = -1;
	input = i_stream_create_file_common(&ustream->fstream, fd, NULL,
					    max_buffer_size, FALSE);
	input->real_stream->iostream.close = i_stream_unix_close;
	input->real_stream->read = i_stream_unix_read;
	return input;
}

void i_stream_unix_set_read_fd(struct istream *input)
{
	struct unix_istream *ustream =
		(struct unix_istream *)input->real_stream;

	ustream->next_read_fd = TRUE;
}

void i_stream_unix_unset_read_fd(struct istream *input)
{
	struct unix_istream *ustream =
		(struct unix_istream *)input->real_stream;

	ustream->next_read_fd = FALSE;
}

int i_stream_unix_get_read_fd(struct istream *input)
{
	struct unix_istream *ustream =
		(struct unix_istream *)input->real_stream;
	int fd;

	fd = ustream->read_fd;
	ustream->read_fd = -1;
	return fd;
}
