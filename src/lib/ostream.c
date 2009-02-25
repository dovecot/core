/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream-internal.h"

void o_stream_destroy(struct ostream **stream)
{
	o_stream_close(*stream);
	o_stream_unref(stream);
}

void o_stream_ref(struct ostream *stream)
{
	io_stream_ref(&stream->real_stream->iostream);
}

void o_stream_unref(struct ostream **stream)
{
	io_stream_unref(&(*stream)->real_stream->iostream);
	*stream = NULL;
}

void o_stream_close(struct ostream *stream)
{
	io_stream_close(&stream->real_stream->iostream);
	stream->closed = TRUE;
}

#undef o_stream_set_flush_callback
void o_stream_set_flush_callback(struct ostream *stream,
				 stream_flush_callback_t *callback,
				 void *context)
{
	struct ostream_private *_stream = stream->real_stream;

	_stream->callback = callback;
	_stream->context = context;
}

void o_stream_unset_flush_callback(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;

	_stream->callback = NULL;
	_stream->context = NULL;
}

void o_stream_set_max_buffer_size(struct ostream *stream, size_t max_size)
{
	io_stream_set_max_buffer_size(&stream->real_stream->iostream, max_size);
}

void o_stream_cork(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed))
		return;

	_stream->cork(_stream, TRUE);
}

void o_stream_uncork(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed))
		return;

	_stream->cork(_stream, FALSE);
}

int o_stream_flush(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;
	int ret;

	if (unlikely(stream->closed))
		return -1;

	stream->stream_errno = 0;
	if (unlikely((ret = _stream->flush(_stream)) < 0)) {
		i_assert(stream->stream_errno != 0);
		stream->last_failed_errno = stream->stream_errno;
	}
	return ret;
}

void o_stream_set_flush_pending(struct ostream *stream, bool set)
{
	struct ostream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed))
		return;

	_stream->flush_pending(_stream, set);
}

size_t o_stream_get_buffer_used_size(const struct ostream *stream)
{
	const struct ostream_private *_stream = stream->real_stream;

	return _stream->get_used_size(_stream);
}

int o_stream_seek(struct ostream *stream, uoff_t offset)
{
	struct ostream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed))
		return -1;

	stream->stream_errno = 0;
	if (unlikely(_stream->seek(_stream, offset) < 0)) {
		i_assert(stream->stream_errno != 0);
		stream->last_failed_errno = stream->stream_errno;
	}
	return 1;
}

ssize_t o_stream_send(struct ostream *stream, const void *data, size_t size)
{
	struct const_iovec iov;

	iov.iov_base = data;
	iov.iov_len = size;

	return o_stream_sendv(stream, &iov, 1);
}

ssize_t o_stream_sendv(struct ostream *stream, const struct const_iovec *iov,
		       unsigned int iov_count)
{
	struct ostream_private *_stream = stream->real_stream;
	unsigned int i;
	size_t total_size;
	ssize_t ret;

	if (unlikely(stream->closed))
		return -1;

	stream->stream_errno = 0;
	for (i = 0, total_size = 0; i < iov_count; i++)
		total_size += iov[i].iov_len;
	if (total_size == 0)
		return 0;

	ret = _stream->sendv(_stream, iov, iov_count);
	if (unlikely(ret != (ssize_t)total_size)) {
		if (ret < 0) {
			i_assert(stream->stream_errno != 0);
			stream->last_failed_errno = stream->stream_errno;
		} else {
			stream->overflow = TRUE;
		}
	}
	return ret;
}

ssize_t o_stream_send_str(struct ostream *stream, const char *str)
{
	return o_stream_send(stream, str, strlen(str));
}

off_t o_stream_send_istream(struct ostream *outstream,
			    struct istream *instream)
{
	struct ostream_private *_outstream = outstream->real_stream;
	off_t ret;

	if (unlikely(outstream->closed || instream->closed))
		return -1;

	outstream->stream_errno = 0;
	ret = _outstream->send_istream(_outstream, instream);
	if (unlikely(ret < 0))
		errno = outstream->stream_errno;
	return ret;
}

int o_stream_pwrite(struct ostream *stream, const void *data, size_t size,
		    uoff_t offset)
{
	int ret;

	if (unlikely(stream->closed))
		return -1;

	ret = stream->real_stream->write_at(stream->real_stream,
					    data, size, offset);
	if (unlikely(ret < 0)) {
		i_assert(stream->stream_errno != 0);
		stream->last_failed_errno = stream->stream_errno;
	}
	return ret;
}

struct ostream *o_stream_create(struct ostream_private *_stream)
{
	_stream->ostream.real_stream = _stream;

	io_stream_init(&_stream->iostream);
	return &_stream->ostream;
}
