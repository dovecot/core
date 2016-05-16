/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream-private.h"

void o_stream_set_name(struct ostream *stream, const char *name)
{
	i_free(stream->real_stream->iostream.name);
	stream->real_stream->iostream.name = i_strdup(name);
}

const char *o_stream_get_name(struct ostream *stream)
{
	while (stream->real_stream->iostream.name == NULL) {
		stream = stream->real_stream->parent;
		if (stream == NULL)
			return "";
	}
	return stream->real_stream->iostream.name;
}

int o_stream_get_fd(struct ostream *stream)
{
	return stream->real_stream->fd;
}

const char *o_stream_get_error(struct ostream *stream)
{
	struct ostream *s;

	/* we'll only return errors for streams that have stream_errno set.
	   we might be returning unintended error otherwise. */
	if (stream->stream_errno == 0)
		return "<no error>";

	for (s = stream; s != NULL; s = s->real_stream->parent) {
		if (s->stream_errno == 0)
			break;
		if (s->real_stream->iostream.error != NULL)
			return s->real_stream->iostream.error;
	}
	return strerror(stream->stream_errno);
}

static void o_stream_close_full(struct ostream *stream, bool close_parents)
{
	if (!stream->closed && !stream->real_stream->closing) {
		/* first mark the stream as being closed so the
		   o_stream_copy_error_from_parent() won't recurse us back
		   here. but don't immediately mark the stream closed, because
		   we may still want to write something to it. */
		stream->real_stream->closing = TRUE;
		io_stream_close(&stream->real_stream->iostream, close_parents);
		stream->closed = TRUE;
	}

	if (stream->stream_errno == 0)
		stream->stream_errno = EPIPE;
}

void o_stream_destroy(struct ostream **stream)
{
	o_stream_close_full(*stream, FALSE);
	o_stream_unref(stream);
}

void o_stream_ref(struct ostream *stream)
{
	io_stream_ref(&stream->real_stream->iostream);
}

void o_stream_unref(struct ostream **_stream)
{
	struct ostream *stream = *_stream;

	if (stream->real_stream->last_errors_not_checked &&
	    !stream->real_stream->error_handling_disabled &&
	    stream->real_stream->iostream.refcount == 1) {
		i_panic("output stream %s is missing error handling",
			o_stream_get_name(stream));
	}

	if (!io_stream_unref(&stream->real_stream->iostream))
		io_stream_free(&stream->real_stream->iostream);
	*_stream = NULL;
}

#undef o_stream_add_destroy_callback
void o_stream_add_destroy_callback(struct ostream *stream,
				   ostream_callback_t *callback, void *context)
{
	io_stream_add_destroy_callback(&stream->real_stream->iostream,
				       callback, context);
}

void o_stream_remove_destroy_callback(struct ostream *stream,
				      void (*callback)())
{
	io_stream_remove_destroy_callback(&stream->real_stream->iostream,
					  callback);
}

void o_stream_close(struct ostream *stream)
{
	o_stream_close_full(stream, TRUE);
}

#undef o_stream_set_flush_callback
void o_stream_set_flush_callback(struct ostream *stream,
				 stream_flush_callback_t *callback,
				 void *context)
{
	struct ostream_private *_stream = stream->real_stream;

	_stream->set_flush_callback(_stream, callback, context);
}

void o_stream_unset_flush_callback(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;

	_stream->set_flush_callback(_stream, NULL, NULL);
}

void o_stream_set_max_buffer_size(struct ostream *stream, size_t max_size)
{
	io_stream_set_max_buffer_size(&stream->real_stream->iostream, max_size);
}

size_t o_stream_get_max_buffer_size(struct ostream *stream)
{
	return stream->real_stream->max_buffer_size;
}

void o_stream_cork(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed || stream->stream_errno != 0))
		return;

	_stream->cork(_stream, TRUE);
}

void o_stream_uncork(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed || stream->stream_errno != 0))
		return;

	_stream->cork(_stream, FALSE);
}

bool o_stream_is_corked(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;

	return _stream->corked;
}

int o_stream_flush(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;
	int ret = 1;

	if (unlikely(stream->closed || stream->stream_errno != 0)) {
		errno = stream->stream_errno;
		return -1;
	}

	if (unlikely((ret = _stream->flush(_stream)) < 0)) {
		i_assert(stream->stream_errno != 0);
		errno = stream->stream_errno;
	}
	return ret;
}

void o_stream_set_flush_pending(struct ostream *stream, bool set)
{
	struct ostream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed || stream->stream_errno != 0))
		return;

	_stream->flush_pending(_stream, set);
}

size_t o_stream_get_buffer_used_size(const struct ostream *stream)
{
	const struct ostream_private *_stream = stream->real_stream;

	return _stream->get_used_size(_stream);
}

size_t o_stream_get_buffer_avail_size(const struct ostream *stream)
{
	size_t used = o_stream_get_buffer_used_size(stream);

	return stream->real_stream->max_buffer_size <= used ? 0 :
		stream->real_stream->max_buffer_size - used;
}

int o_stream_seek(struct ostream *stream, uoff_t offset)
{
	struct ostream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed || stream->stream_errno != 0)) {
		errno = stream->stream_errno;
		return -1;
	}

	if (unlikely(_stream->seek(_stream, offset) < 0)) {
		i_assert(stream->stream_errno != 0);
		errno = stream->stream_errno;
		return -1;
	}
	return 1;
}

ssize_t o_stream_send(struct ostream *stream, const void *data, size_t size)
{
	struct const_iovec iov;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = data;
	iov.iov_len = size;

 	return o_stream_sendv(stream, &iov, 1);
}

static ssize_t
o_stream_sendv_int(struct ostream *stream, const struct const_iovec *iov,
		   unsigned int iov_count, bool *overflow_r)
{
	struct ostream_private *_stream = stream->real_stream;
	unsigned int i;
	size_t total_size;
	ssize_t ret;

	*overflow_r = FALSE;

	for (i = 0, total_size = 0; i < iov_count; i++)
		total_size += iov[i].iov_len;
	if (total_size == 0)
		return 0;

	ret = _stream->sendv(_stream, iov, iov_count);
	if (unlikely(ret != (ssize_t)total_size)) {
		if (ret < 0) {
			i_assert(stream->stream_errno != 0);
			errno = stream->stream_errno;
		} else {
			i_assert(!stream->blocking);
			stream->overflow = TRUE;
			*overflow_r = TRUE;
		}
	}
	return ret;
}

ssize_t o_stream_sendv(struct ostream *stream, const struct const_iovec *iov,
		       unsigned int iov_count)
{
	bool overflow;

	if (unlikely(stream->closed || stream->stream_errno != 0)) {
		errno = stream->stream_errno;
		return -1;
	}
	return o_stream_sendv_int(stream, iov, iov_count, &overflow);
}

ssize_t o_stream_send_str(struct ostream *stream, const char *str)
{
	return o_stream_send(stream, str, strlen(str));
}

void o_stream_nsend(struct ostream *stream, const void *data, size_t size)
{
	struct const_iovec iov;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = data;
	iov.iov_len = size;

	o_stream_nsendv(stream, &iov, 1);
}

void o_stream_nsendv(struct ostream *stream, const struct const_iovec *iov,
		     unsigned int iov_count)
{
	bool overflow;

	if (unlikely(stream->closed || stream->stream_errno != 0 ||
		     stream->real_stream->noverflow))
		return;
	(void)o_stream_sendv_int(stream, iov, iov_count, &overflow);
	if (overflow)
		stream->real_stream->noverflow = TRUE;
	stream->real_stream->last_errors_not_checked = TRUE;
}

void o_stream_nsend_str(struct ostream *stream, const char *str)
{
	o_stream_nsend(stream, str, strlen(str));
}

void o_stream_nflush(struct ostream *stream)
{
	if (unlikely(stream->closed || stream->stream_errno != 0))
		return;
	(void)o_stream_flush(stream);
	stream->real_stream->last_errors_not_checked = TRUE;
}

int o_stream_nfinish(struct ostream *stream)
{
	o_stream_nflush(stream);
	o_stream_ignore_last_errors(stream);
	if (stream->stream_errno == 0 && stream->real_stream->noverflow) {
		io_stream_set_error(&stream->real_stream->iostream,
			"Output stream buffer was full (%"PRIuSIZE_T" bytes)",
			o_stream_get_max_buffer_size(stream));
		stream->stream_errno = ENOBUFS;
	}
	return stream->stream_errno != 0 ? -1 : 0;
}

void o_stream_ignore_last_errors(struct ostream *stream)
{
	while (stream != NULL) {
		stream->real_stream->last_errors_not_checked = FALSE;
		stream = stream->real_stream->parent;
	}
}

void o_stream_set_no_error_handling(struct ostream *stream, bool set)
{
	stream->real_stream->error_handling_disabled = set;
}

off_t o_stream_send_istream(struct ostream *outstream,
			    struct istream *instream)
{
	struct ostream_private *_outstream = outstream->real_stream;
	off_t ret;

	if (unlikely(outstream->closed || instream->closed ||
		     outstream->stream_errno != 0)) {
		errno = outstream->stream_errno;
		return -1;
	}

	ret = _outstream->send_istream(_outstream, instream);
	if (unlikely(ret < 0)) {
		if (outstream->stream_errno != 0) {
			errno = outstream->stream_errno;
		} else {
			i_assert(instream->stream_errno != 0);
		}
	}
	return ret;
}

int o_stream_pwrite(struct ostream *stream, const void *data, size_t size,
		    uoff_t offset)
{
	int ret;

	if (unlikely(stream->closed || stream->stream_errno != 0)) {
		errno = stream->stream_errno;
		return -1;
	}

	ret = stream->real_stream->write_at(stream->real_stream,
					    data, size, offset);
	if (unlikely(ret < 0)) {
		i_assert(stream->stream_errno != 0);
		errno = stream->stream_errno;
	}
	return ret;
}

off_t io_stream_copy(struct ostream *outstream, struct istream *instream)
{
	uoff_t start_offset;
	struct const_iovec iov;
	const unsigned char *data;
	ssize_t ret;

	start_offset = instream->v_offset;
	do {
		(void)i_stream_read_more(instream, &data, &iov.iov_len);
		if (iov.iov_len == 0) {
			/* all sent */
			if (instream->stream_errno != 0)
				return -1;
			break;
		}

		iov.iov_base = data;
		ret = o_stream_sendv(outstream, &iov, 1);
		if (ret <= 0) {
			if (ret == 0)
				break;
			return -1;
		}
		i_stream_skip(instream, ret);
	} while ((size_t)ret == iov.iov_len);

	return (off_t)(instream->v_offset - start_offset);
}

void o_stream_switch_ioloop(struct ostream *stream)
{
	struct ostream_private *_stream = stream->real_stream;

	_stream->switch_ioloop(_stream);
}

static void o_stream_default_close(struct iostream_private *stream,
				   bool close_parent)
{
	struct ostream_private *_stream = (struct ostream_private *)stream;

	(void)o_stream_flush(&_stream->ostream);
	if (close_parent && _stream->parent != NULL)
		o_stream_close(_stream->parent);
}

static void o_stream_default_destroy(struct iostream_private *stream)
{
	struct ostream_private *_stream = (struct ostream_private *)stream;

	if (_stream->parent != NULL)
		o_stream_unref(&_stream->parent);
}

static void
o_stream_default_set_max_buffer_size(struct iostream_private *stream,
				     size_t max_size)
{
	struct ostream_private *_stream = (struct ostream_private *)stream;

	if (_stream->parent != NULL)
		o_stream_set_max_buffer_size(_stream->parent, max_size);
	_stream->max_buffer_size = max_size;
}

static void o_stream_default_cork(struct ostream_private *_stream, bool set)
{
	_stream->corked = set;
	if (set) {
		if (_stream->parent != NULL)
			o_stream_cork(_stream->parent);
	} else {
		(void)o_stream_flush(&_stream->ostream);
		if (_stream->parent != NULL)
			o_stream_uncork(_stream->parent);
	}
}

void o_stream_copy_error_from_parent(struct ostream_private *_stream)
{
	struct ostream *src = _stream->parent;
	struct ostream *dest = &_stream->ostream;

	dest->stream_errno = src->stream_errno;
	dest->overflow = src->overflow;
	if (src->closed)
		o_stream_close(dest);
}

int o_stream_flush_parent_if_needed(struct ostream_private *_stream)
{
	if (o_stream_get_buffer_used_size(_stream->parent) >= IO_BLOCK_SIZE) {
		/* we already have quite a lot of data in parent stream.
		   unless we can flush it, don't add any more to it or we
		   could keep wasting memory by just increasing the buffer
		   size all the time. */
		if (o_stream_flush(_stream->parent) < 0) {
			o_stream_copy_error_from_parent(_stream);
			return -1;
		}
		if (o_stream_get_buffer_used_size(_stream->parent) >= IO_BLOCK_SIZE)
			return 0;
	}
	return 1;
}

static int o_stream_default_flush(struct ostream_private *_stream)
{
	int ret;

	if (_stream->parent == NULL)
		return 1;

	if ((ret = o_stream_flush(_stream->parent)) < 0)
		o_stream_copy_error_from_parent(_stream);
	return ret;
}

static void
o_stream_default_set_flush_callback(struct ostream_private *_stream,
				    stream_flush_callback_t *callback,
				    void *context)
{
	if (_stream->parent != NULL)
		o_stream_set_flush_callback(_stream->parent, callback, context);

	_stream->callback = callback;
	_stream->context = context;
}

static void
o_stream_default_set_flush_pending(struct ostream_private *_stream, bool set)
{
	if (_stream->parent != NULL)
		o_stream_set_flush_pending(_stream->parent, set);
}

static size_t
o_stream_default_get_used_size(const struct ostream_private *_stream)
{
	if (_stream->parent == NULL)
		return 0;
	else
		return o_stream_get_buffer_used_size(_stream->parent);
}

static int
o_stream_default_seek(struct ostream_private *_stream,
		      uoff_t offset ATTR_UNUSED)
{
	_stream->ostream.stream_errno = ESPIPE;
	return -1;
}

static ssize_t
o_stream_default_sendv(struct ostream_private *stream,
		       const struct const_iovec *iov, unsigned int iov_count)
{
	ssize_t ret;

	if ((ret = o_stream_sendv(stream->parent, iov, iov_count)) < 0) {
		o_stream_copy_error_from_parent(stream);
		return -1;
	}
	stream->ostream.offset += ret;
	return ret;
}

static int
o_stream_default_write_at(struct ostream_private *_stream,
			  const void *data ATTR_UNUSED,
			  size_t size ATTR_UNUSED, uoff_t offset ATTR_UNUSED)
{
	_stream->ostream.stream_errno = ESPIPE;
	return -1;
}

static off_t o_stream_default_send_istream(struct ostream_private *outstream,
					   struct istream *instream)
{
	return io_stream_copy(&outstream->ostream, instream);
}

static void o_stream_default_switch_ioloop(struct ostream_private *_stream)
{
	if (_stream->parent != NULL)
		o_stream_switch_ioloop(_stream->parent);
}

struct ostream *
o_stream_create(struct ostream_private *_stream, struct ostream *parent, int fd)
{
	_stream->fd = fd;
	_stream->ostream.real_stream = _stream;
	if (parent != NULL) {
		_stream->ostream.blocking = parent->blocking;
		_stream->parent = parent;
		o_stream_ref(parent);

		_stream->callback = parent->real_stream->callback;
		_stream->context = parent->real_stream->context;
		_stream->max_buffer_size = parent->real_stream->max_buffer_size;
		_stream->error_handling_disabled =
			parent->real_stream->error_handling_disabled;
	}

	if (_stream->iostream.close == NULL)
		_stream->iostream.close = o_stream_default_close;
	if (_stream->iostream.destroy == NULL)
		_stream->iostream.destroy = o_stream_default_destroy;
	if (_stream->iostream.set_max_buffer_size == NULL) {
		_stream->iostream.set_max_buffer_size =
			o_stream_default_set_max_buffer_size;
	}

	if (_stream->cork == NULL)
		_stream->cork = o_stream_default_cork;
	if (_stream->flush == NULL)
		_stream->flush = o_stream_default_flush;
	if (_stream->set_flush_callback == NULL) {
		_stream->set_flush_callback =
			o_stream_default_set_flush_callback;
	}
	if (_stream->flush_pending == NULL)
		_stream->flush_pending = o_stream_default_set_flush_pending;
	if (_stream->get_used_size == NULL)
		_stream->get_used_size = o_stream_default_get_used_size;
	if (_stream->seek == NULL)
		_stream->seek = o_stream_default_seek;
	if (_stream->sendv == NULL)
		_stream->sendv = o_stream_default_sendv;
	if (_stream->write_at == NULL)
		_stream->write_at = o_stream_default_write_at;
	if (_stream->send_istream == NULL)
		_stream->send_istream = o_stream_default_send_istream;
	if (_stream->switch_ioloop == NULL)
		_stream->switch_ioloop = o_stream_default_switch_ioloop;

	io_stream_init(&_stream->iostream);
	return &_stream->ostream;
}

struct ostream *o_stream_create_error(int stream_errno)
{
	struct ostream_private *stream;
	struct ostream *output;

	stream = i_new(struct ostream_private, 1);
	stream->ostream.blocking = TRUE;
	stream->ostream.closed = TRUE;
	stream->ostream.stream_errno = stream_errno;

	output = o_stream_create(stream, NULL, -1);
	o_stream_set_no_error_handling(output, TRUE);
	o_stream_set_name(output, "(error)");
	return output;
}

struct ostream *
o_stream_create_error_str(int stream_errno, const char *fmt, ...)
{
	struct ostream *output;
	va_list args;

	va_start(args, fmt);
	output = o_stream_create_error(stream_errno);
	io_stream_set_verror(&output->real_stream->iostream, fmt, args);
	va_end(args);
	return output;
}

struct ostream *o_stream_create_passthrough(struct ostream *output)
{
	struct ostream_private *stream;

	stream = i_new(struct ostream_private, 1);
	return o_stream_create(stream, output, o_stream_get_fd(output));
}
