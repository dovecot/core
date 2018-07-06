/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "iostream-openssl.h"

struct ssl_istream {
	struct istream_private istream;
	struct ssl_iostream *ssl_io;
	bool seen_eof;
};

static void i_stream_ssl_close(struct iostream_private *stream,
			       bool close_parent)
{
	struct ssl_istream *sstream = (struct ssl_istream *)stream;

	if (close_parent)
		i_stream_close(sstream->ssl_io->plain_input);
}

static void i_stream_ssl_destroy(struct iostream_private *stream)
{
	struct ssl_istream *sstream = (struct ssl_istream *)stream;

	openssl_iostream_shutdown(sstream->ssl_io);
	i_stream_free_buffer(&sstream->istream);
	sstream->ssl_io->ssl_input = NULL;
	ssl_iostream_unref(&sstream->ssl_io);
}

static ssize_t i_stream_ssl_read_real(struct istream_private *stream)
{
	struct ssl_istream *sstream = (struct ssl_istream *)stream;
	struct ssl_iostream *ssl_io = sstream->ssl_io;
	unsigned char buffer[IO_BLOCK_SIZE];
	size_t orig_max_buffer_size = stream->max_buffer_size;
	size_t size;
	ssize_t ret, total_ret;

	if (sstream->seen_eof) {
		stream->istream.eof = TRUE;
		return -1;
	}

	ret = openssl_iostream_more(ssl_io,
		OPENSSL_IOSTREAM_SYNC_TYPE_HANDSHAKE);
	if (ret <= 0) {
		if (ret < 0) {
			/* handshake failed */
			i_assert(errno != 0);
			io_stream_set_error(&stream->iostream,
					    "%s", ssl_io->last_error);
			stream->istream.stream_errno = errno;
		}
		return ret;
	}
	if (!i_stream_try_alloc(stream, 1, &size))
		return -2;

	while ((ret = SSL_read(ssl_io->ssl,
			       stream->w_buffer + stream->pos, size)) <= 0) {
		/* failed to read anything */
		ret = openssl_iostream_handle_error(ssl_io, ret,
			OPENSSL_IOSTREAM_SYNC_TYPE_CONTINUE_READ, "SSL_read");
		if (ret <= 0) {
			if (ret == 0)
				return 0;
			if (ssl_io->last_error != NULL) {
				io_stream_set_error(&stream->iostream,
						    "%s", ssl_io->last_error);
			}
			if (errno != EPIPE)
				stream->istream.stream_errno = errno;
			stream->istream.eof = TRUE;
			sstream->seen_eof = TRUE;
			return -1;
		}
		/* we did some BIO I/O, try reading again */
	}
	stream->pos += ret;
	total_ret = ret;

	/* now make sure that we read everything already buffered in OpenSSL
	   into the stream (without reading anything more). this makes I/O loop
	   behave similarly for ssl-istream as file-istream. */
	stream->max_buffer_size = (size_t)-1;
	while ((ret = SSL_read(ssl_io->ssl, buffer, sizeof(buffer))) > 0) {
		memcpy(i_stream_alloc(stream, ret), buffer, ret);
		stream->pos += ret;
		total_ret += ret;
	}
	stream->max_buffer_size = orig_max_buffer_size;
	return total_ret;
}

static ssize_t i_stream_ssl_read(struct istream_private *stream)
{
	struct ssl_istream *sstream = (struct ssl_istream *)stream;
	ssize_t ret;

	if ((ret = i_stream_ssl_read_real(stream)) >= 0) {
		i_assert(i_stream_get_data_size(sstream->ssl_io->plain_input) == 0);
	}
	return ret;
}

struct istream *openssl_i_stream_create_ssl(struct ssl_iostream *ssl_io)
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
	return i_stream_create(&sstream->istream, NULL,
			       i_stream_get_fd(ssl_io->plain_input), 0);
}
