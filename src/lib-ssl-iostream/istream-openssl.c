/* Copyright (c) 2009-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "iostream-openssl.h"

struct ssl_istream {
	struct istream_private istream;
	struct ssl_iostream *ssl_io;
	bool seen_eof;
};

static void i_stream_ssl_close(struct iostream_private *stream)
{
	struct ssl_istream *sstream = (struct ssl_istream *)stream;

	i_stream_close(sstream->ssl_io->plain_input);
}

static void i_stream_ssl_destroy(struct iostream_private *stream)
{
	struct ssl_istream *sstream = (struct ssl_istream *)stream;

	i_free(sstream->istream.w_buffer);
	ssl_iostream_unref(&sstream->ssl_io);
}

static ssize_t i_stream_ssl_read(struct istream_private *stream)
{
	struct ssl_istream *sstream = (struct ssl_istream *)stream;
	size_t size;
	ssize_t ret;

	if (sstream->seen_eof) {
		stream->istream.eof = TRUE;
		return -1;
	}
	ret = ssl_iostream_more(sstream->ssl_io);
	if (ret <= 0) {
		if (ret < 0) {
			/* handshake failed */
			i_assert(errno != 0);
			stream->istream.stream_errno = errno;
		}
		return ret;
	}

	if (!i_stream_try_alloc(stream, 1, &size))
		return -2;

	while ((ret = SSL_read(sstream->ssl_io->ssl,
			       stream->w_buffer + stream->pos, size)) <= 0) {
		/* failed to read anything */
		ret = ssl_iostream_handle_error(sstream->ssl_io, ret,
						"SSL_read");
		if (ret <= 0) {
			if (ret < 0) {
				stream->istream.stream_errno = errno;
				stream->istream.eof = TRUE;
				sstream->seen_eof = TRUE;
			}
			return ret;
		}
		/* we did some BIO I/O, try reading again */
	}
	stream->pos += ret;
	return ret;
}

struct istream *i_stream_create_ssl(struct ssl_iostream *ssl_io)
{
	struct ssl_istream *sstream;

	ssl_io->refcount++;

	sstream = i_new(struct ssl_istream, 1);
	sstream->ssl_io = ssl_io;
	sstream->istream.iostream.close = i_stream_ssl_close;
	sstream->istream.iostream.destroy = i_stream_ssl_destroy;
	sstream->istream.max_buffer_size =
		ssl_io->plain_input->real_stream->max_buffer_size;
	sstream->istream.read = i_stream_ssl_read;

	sstream->istream.istream.readable_fd = FALSE;
	return i_stream_create(&sstream->istream, NULL, -1);
}
