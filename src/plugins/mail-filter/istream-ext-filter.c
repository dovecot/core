/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "net.h"
#include "eacces-error.h"
#include "fd-set-nonblock.h"
#include "ostream.h"
#include "istream-private.h"
#include "istream-ext-filter.h"

#include <unistd.h>

struct mail_filter_istream {
	struct istream_private istream;

	int fd;
	struct istream *ext_in;
	struct ostream *ext_out;
	size_t prev_ret;
};

static void
i_stream_mail_filter_close(struct iostream_private *stream, bool close_parent)
{
	struct mail_filter_istream *mstream =
		(struct mail_filter_istream *)stream;

	if (mstream->ext_in != NULL)
		i_stream_destroy(&mstream->ext_in);
	if (mstream->ext_out != NULL)
		o_stream_destroy(&mstream->ext_out);
	if (mstream->fd != -1) {
		if (close(mstream->fd) < 0)
			i_error("ext-filter: close() failed: %m");
		mstream->fd = -1;
	}
	if (close_parent)
		i_stream_close(mstream->istream.parent);
}

static ssize_t
i_stream_read_copy_from(struct istream *istream, struct istream *source)
{
	struct istream_private *stream = istream->real_stream;
	size_t pos;
	ssize_t ret;

	stream->pos -= stream->skip;
	stream->skip = 0;

	stream->buffer = i_stream_get_data(source, &pos);
	if (pos > stream->pos)
		ret = 0;
	else do {
		if ((ret = i_stream_read(source)) == -2)
			return -2;

		stream->istream.stream_errno = source->stream_errno;
		stream->istream.eof = source->eof;
		stream->buffer = i_stream_get_data(source, &pos);
		/* check again, in case the source stream had been seeked
		   backwards and the previous read() didn't get us far
		   enough. */
	} while (pos <= stream->pos && ret > 0);

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = pos;
	i_assert(ret != -1 || stream->istream.eof ||
		 stream->istream.stream_errno != 0);
	return ret;
}

static ssize_t
i_stream_mail_filter_read_once(struct mail_filter_istream *mstream)
{
	struct istream_private *stream = &mstream->istream;
	ssize_t ret;

	if (mstream->ext_out != NULL) {
		/* we haven't sent everything yet */
		(void)o_stream_send_istream(mstream->ext_out, stream->parent);
		if (mstream->ext_out->stream_errno != 0) {
			stream->istream.stream_errno =
				mstream->ext_out->stream_errno;
			return -1;
		}
		if (i_stream_is_eof(stream->parent)) {
			o_stream_destroy(&mstream->ext_out);
			/* if we wanted to be a blocking stream,
			   from now on the rest of the reads are */
			if (stream->istream.blocking)
				net_set_nonblock(mstream->fd, FALSE);
			if (shutdown(mstream->fd, SHUT_WR) < 0)
				i_error("ext-filter: shutdown() failed: %m");
		}
	}

	i_stream_skip(mstream->ext_in, mstream->prev_ret);
	ret = i_stream_read_copy_from(&stream->istream, mstream->ext_in);
	mstream->prev_ret = ret < 0 ? 0 : ret;
	return ret;
}

static ssize_t i_stream_mail_filter_read(struct istream_private *stream)
{
	struct mail_filter_istream *mstream =
		(struct mail_filter_istream *)stream;
	ssize_t ret;

	if (mstream->ext_in == NULL) {
		stream->istream.stream_errno = EIO;
		return -1;
	}

	while ((ret = i_stream_mail_filter_read_once(mstream)) == 0) {
		if (!stream->istream.blocking)
			break;
	}
	return ret;
}

static int
i_stream_mail_filter_stat(struct istream_private *stream, bool exact)
{
	const struct stat *st;

	i_assert(!exact);

	if (i_stream_stat(stream->parent, exact, &st) < 0)
		return -1;
	stream->statbuf = *st;
	return 0;
}

static int filter_connect(struct mail_filter_istream *mstream,
			  const char *socket_path, const char *args)
{
	const char **argv;
	string_t *str;
	int fd;

	argv = t_strsplit(args, " ");

	if ((fd = net_connect_unix_with_retries(socket_path, 1000)) < 0) {
		if (errno == EACCES) {
			i_error("ext-filter: %s",
				eacces_error_get("net_connect_unix",
						 socket_path));
		} else {
			i_error("ext-filter: net_connect_unix(%s) failed: %m",
				socket_path);
		}
		return -1;
	}
	if (mstream->istream.istream.blocking)
		net_set_nonblock(fd, FALSE);

	mstream->fd = fd;
	mstream->ext_in =
		i_stream_create_fd(fd, mstream->istream.max_buffer_size, FALSE);
	mstream->ext_out = o_stream_create_fd(fd, 0, FALSE);

	str = t_str_new(256);
	str_append(str, "VERSION\tscript\t3\t0\nnoreply\n");
	for (; *argv != NULL; argv++) {
		str_append(str, *argv);
		str_append_c(str, '\n');
	}
	str_append_c(str, '\n');

	o_stream_send(mstream->ext_out, str_data(str), str_len(str));
	return 0;
}

struct istream *
i_stream_create_ext_filter(struct istream *input, const char *socket_path,
			   const char *args)
{
	struct mail_filter_istream *mstream;

	mstream = i_new(struct mail_filter_istream, 1);
	mstream->istream.iostream.close = i_stream_mail_filter_close;
	mstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	mstream->istream.read = i_stream_mail_filter_read;
	mstream->istream.stat = i_stream_mail_filter_stat;

	mstream->istream.istream.readable_fd = FALSE;
	mstream->istream.istream.blocking = input->blocking;
	mstream->istream.istream.seekable = FALSE;

	mstream->fd = -1;
	(void)filter_connect(mstream, socket_path, args);

	return i_stream_create(&mstream->istream, input, mstream->fd);
}
