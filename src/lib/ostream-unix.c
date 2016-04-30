/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fdpass.h"
#include "ostream-file-private.h"
#include "ostream-unix.h"

struct unix_ostream {
	struct file_ostream fstream;
	int write_fd;
};

static void
o_stream_unix_close(struct iostream_private *stream, bool close_parent)
{
	struct unix_ostream *ustream = (struct unix_ostream *)stream;

	if (ustream->write_fd != -1)
		i_close_fd(&ustream->write_fd);
	o_stream_file_close(stream, close_parent);
}

static ssize_t o_stream_unix_writev(struct file_ostream *fstream,
				   const struct const_iovec *iov,
				   unsigned int iov_count)
{
	struct unix_ostream *ustream = (struct unix_ostream *)fstream;
	size_t sent;
	ssize_t ret;

	if (ustream->write_fd == -1) {
		/* no fd */
		return o_stream_file_writev(fstream, iov, iov_count);
	}

	/* send first iovec along with fd */
	if (iov_count == 0)
		return 0;
	i_assert(iov[0].iov_len > 0);
	ret = fd_send(fstream->fd, ustream->write_fd,
		iov[0].iov_base, iov[0].iov_len);
	if (ret < 0)
		return ret;

	/* update stream */
	sent = ret;
	fstream->real_offset += sent;

	ustream->write_fd = -1;

	if (sent < iov[0].iov_len || iov_count == 1) {
		/* caller will call us again to write the rest */
		return sent;
	}

	/* send remaining iovecs */
	ret = o_stream_file_writev(fstream, &iov[1], iov_count-1);
	if (ret < 0)
		return  (errno == EAGAIN || errno == EINTR ? (ssize_t)sent : ret);
	sent += ret;
	return sent;
}

struct ostream *o_stream_create_unix(int fd, size_t max_buffer_size)
{
	struct unix_ostream *ustream;
	struct ostream *output;

	i_assert(fd != -1);

	ustream = i_new(struct unix_ostream, 1);
	ustream->write_fd = -1;
	output = o_stream_create_file_common(&ustream->fstream, fd,
					    max_buffer_size, FALSE);
	output->real_stream->iostream.close = o_stream_unix_close;
	ustream->fstream.writev = o_stream_unix_writev;

	return output;
}

bool o_stream_unix_write_fd(struct ostream *output, int fd)
{
	struct unix_ostream *ustream =
		(struct unix_ostream *)output->real_stream;

	if (ustream->write_fd >= 0)
		return FALSE;
	ustream->write_fd = fd;
	return TRUE;
}
