/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "ostream-internal.h"
#include "iostream-openssl.h"

struct ssl_ostream {
	struct ostream_private ostream;
	struct ssl_iostream *ssl_io;
	buffer_t *buffer;
};

static void i_stream_ssl_destroy(struct iostream_private *stream)
{
	struct ssl_ostream *sstream = (struct ssl_ostream *)stream;

	sstream->ssl_io->ssl_output = NULL;
	ssl_iostream_unref(&sstream->ssl_io);
	i_free(sstream->buffer);
}

static size_t
o_stream_ssl_buffer(struct ssl_ostream *sstream, const struct const_iovec *iov,
		    unsigned int iov_count, size_t bytes_sent)
{
	size_t avail, skip_left, size;
	unsigned int i;

	if (sstream->buffer == NULL)
		sstream->buffer = buffer_create_dynamic(default_pool, 4096);

	skip_left = bytes_sent;
	for (i = 0; i < iov_count; i++) {
		if (skip_left < iov[i].iov_len)
			break;
		skip_left -= iov[i].iov_len;
	}

	avail = sstream->ostream.max_buffer_size > sstream->buffer->used ?
		sstream->ostream.max_buffer_size - sstream->buffer->used : 0;
	if (i < iov_count && skip_left > 0) {
		size = I_MIN(iov[i].iov_len - skip_left, avail);
		buffer_append(sstream->buffer,
			      CONST_PTR_OFFSET(iov[i].iov_base, skip_left),
			      size);
		bytes_sent += size;
		avail -= size;
		if (size != iov[i].iov_len)
			i = iov_count;
	}
	for (; i < iov_count; i++) {
		size = I_MIN(iov[i].iov_len, avail);
		buffer_append(sstream->buffer, iov[i].iov_base, size);
		bytes_sent += size;
		avail -= size;

		if (size != iov[i].iov_len)
			break;
	}

	sstream->ostream.ostream.offset += bytes_sent;
	return bytes_sent;
}

static int o_stream_ssl_flush_buffer(struct ssl_ostream *sstream)
{
	size_t pos = 0;
	int ret;

	while (pos < sstream->buffer->used) {
		ret = SSL_write(sstream->ssl_io->ssl,
				CONST_PTR_OFFSET(sstream->buffer->data, pos),
				sstream->buffer->used - pos);
		if (ret <= 0) {
			ret = ssl_iostream_handle_error(sstream->ssl_io, ret,
							"SSL_write");
			if (ret <= 0) {
				if (ret < 0) {
					sstream->ostream.ostream.stream_errno =
						errno;
				}
				buffer_delete(sstream->buffer, 0, pos);
				return ret;
			}
		} else {
			pos += ret;
			(void)ssl_iostream_bio_sync(sstream->ssl_io);
		}
	}
	buffer_delete(sstream->buffer, 0, pos);
	return 1;
}

static int o_stream_ssl_flush(struct ostream_private *stream)
{
	struct ssl_ostream *sstream = (struct ssl_ostream *)stream;
	int ret;

	if (!sstream->ssl_io->handshaked) {
		if ((ret = ssl_iostream_handshake(sstream->ssl_io)) <= 0) {
			if (ret < 0)
				stream->ostream.stream_errno = errno;
			return ret;
		}
	}

	if (sstream->buffer != NULL && sstream->buffer->used > 0) {
		if ((ret = o_stream_ssl_flush_buffer(sstream)) <= 0)
			return ret;
	}
	return 1;
}

static ssize_t
o_stream_ssl_sendv(struct ostream_private *stream,
		   const struct const_iovec *iov, unsigned int iov_count)
{
	struct ssl_ostream *sstream = (struct ssl_ostream *)stream;
	unsigned int i;
	size_t bytes_sent = 0;
	size_t pos;
	int ret = 0;

	if (o_stream_flush(&stream->ostream) <= 0)
		return o_stream_ssl_buffer(sstream, iov, iov_count, 0);

	for (i = 0, pos = 0; i < iov_count; ) {
		ret = SSL_write(sstream->ssl_io->ssl,
				CONST_PTR_OFFSET(iov[i].iov_base, pos),
				iov[i].iov_len - pos);
		if (ret <= 0) {
			ret = ssl_iostream_handle_error(sstream->ssl_io, ret,
							"SSL_write");
			if (ret <= 0) {
				if (ret < 0)
					stream->ostream.stream_errno = errno;
				break;
			}
		} else {
			bytes_sent += ret;
			if ((size_t)ret < iov[i].iov_len)
				pos += ret;
			else {
				i++;
				pos = 0;
			}
			(void)ssl_iostream_bio_sync(sstream->ssl_io);
		}
	}
	bytes_sent = o_stream_ssl_buffer(sstream, iov, iov_count, bytes_sent);
	return bytes_sent != 0 ? (ssize_t)bytes_sent : ret;
}

static int plain_flush_callback(struct ssl_ostream *sstream)
{
	int ret;

	if ((ret = o_stream_flush(sstream->ssl_io->plain_output)) < 0)
		return 1;

	if (ret > 0)
		return o_stream_flush(&sstream->ostream.ostream);
	return 1;
}

struct ostream *o_stream_create_ssl(struct ssl_iostream *ssl_io)
{
	struct ssl_ostream *sstream;

	ssl_io->refcount++;

	sstream = i_new(struct ssl_ostream, 1);
	sstream->ssl_io = ssl_io;
	sstream->ostream.max_buffer_size =
		ssl_io->plain_output->real_stream->max_buffer_size;
	sstream->ostream.iostream.destroy = i_stream_ssl_destroy;
	sstream->ostream.sendv = o_stream_ssl_sendv;
	sstream->ostream.flush = o_stream_ssl_flush;

	o_stream_set_flush_callback(ssl_io->plain_output,
				    plain_flush_callback, sstream);

	return o_stream_create(&sstream->ostream);
}
