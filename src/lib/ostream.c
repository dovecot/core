/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

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
	/* Ideally o_stream_finish() would be called for all non-failed
	   ostreams, but strictly requiring it would cause unnecessary
	   complexity for many callers. Just require that at this point
	   after flushing there isn't anything in the output buffer or that
	   we're ignoring all errors. */
	if (o_stream_flush(stream) == 0)
		i_assert(stream->real_stream->error_handling_disabled);

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
	if (*stream == NULL)
		return;

	o_stream_close_full(*stream, FALSE);
	o_stream_unref(stream);
}

void o_stream_ref(struct ostream *stream)
{
	io_stream_ref(&stream->real_stream->iostream);
}

void o_stream_unref(struct ostream **_stream)
{
	struct ostream *stream;

	if (*_stream == NULL)
		return;

	stream = *_stream;

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
	if (stream != NULL)
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

	o_stream_ignore_last_errors(stream);

	if (unlikely(stream->closed || stream->stream_errno != 0)) {
		errno = stream->stream_errno;
		return -1;
	}

	if (unlikely(_stream->noverflow)) {
		io_stream_set_error(&_stream->iostream,
			"Output stream buffer was full (%zu bytes)",
			o_stream_get_max_buffer_size(stream));
		errno = stream->stream_errno = ENOBUFS;
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

	return _stream->get_buffer_used_size(_stream);
}

size_t o_stream_get_buffer_avail_size(const struct ostream *stream)
{
	const struct ostream_private *_stream = stream->real_stream;

	return _stream->get_buffer_avail_size(_stream);
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

	i_zero(&iov);
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

	i_assert(!_stream->finished);
	ret = _stream->sendv(_stream, iov, iov_count);
	if (ret > 0)
		stream->real_stream->last_write_timeval = ioloop_timeval;
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

	i_zero(&iov);
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

int o_stream_finish(struct ostream *stream)
{
	stream->real_stream->finished = TRUE;
	return o_stream_flush(stream);
}

void o_stream_set_finish_also_parent(struct ostream *stream, bool set)
{
	stream->real_stream->finish_also_parent = set;
}

void o_stream_set_finish_via_child(struct ostream *stream, bool set)
{
	stream->real_stream->finish_via_child = set;
}

void o_stream_ignore_last_errors(struct ostream *stream)
{
	while (stream != NULL) {
		stream->real_stream->last_errors_not_checked = FALSE;
		stream = stream->real_stream->parent;
	}
}

void o_stream_abort(struct ostream *stream)
{
	o_stream_ignore_last_errors(stream);
	if (stream->stream_errno != 0)
		return;
	io_stream_set_error(&stream->real_stream->iostream, "aborted writing");
	stream->stream_errno = EPIPE;
}

void o_stream_set_no_error_handling(struct ostream *stream, bool set)
{
	stream->real_stream->error_handling_disabled = set;
}

enum ostream_send_istream_result
o_stream_send_istream(struct ostream *outstream, struct istream *instream)
{
	struct ostream_private *_outstream = outstream->real_stream;
	uoff_t old_outstream_offset = outstream->offset;
	uoff_t old_instream_offset = instream->v_offset;
	enum ostream_send_istream_result res;

	if (unlikely(instream->closed || instream->stream_errno != 0)) {
		errno = instream->stream_errno;
		return OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT;
	}
	if (unlikely(outstream->closed || outstream->stream_errno != 0)) {
		errno = outstream->stream_errno;
		return OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT;
	}

	i_assert(!_outstream->finished);
	res = _outstream->send_istream(_outstream, instream);
	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		i_assert(instream->stream_errno == 0);
		i_assert(outstream->stream_errno == 0);
		i_assert(!i_stream_have_bytes_left(instream));
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		i_assert(!instream->blocking);
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		i_assert(!outstream->blocking);
		o_stream_set_flush_pending(outstream, TRUE);
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		i_assert(instream->stream_errno != 0);
		return res;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		i_assert(outstream->stream_errno != 0);
		return res;
	}
	/* non-failure - make sure stream offsets match */
	i_assert((outstream->offset - old_outstream_offset) ==
		 (instream->v_offset - old_instream_offset));

	if (outstream->offset != old_outstream_offset)
		outstream->real_stream->last_write_timeval = ioloop_timeval;
	return res;
}

void o_stream_nsend_istream(struct ostream *outstream, struct istream *instream)
{
	i_assert(instream->blocking);

	switch (o_stream_send_istream(outstream, instream)) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		i_unreached();
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		outstream->real_stream->noverflow = TRUE;
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		outstream->stream_errno = instream->stream_errno;
		io_stream_set_error(&outstream->real_stream->iostream,
			"nsend-istream: read(%s) failed: %s",
			i_stream_get_name(instream),
			i_stream_get_error(instream));
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		break;
	}
	outstream->real_stream->last_errors_not_checked = TRUE;
}

int o_stream_pwrite(struct ostream *stream, const void *data, size_t size,
		    uoff_t offset)
{
	int ret;

	if (unlikely(stream->closed || stream->stream_errno != 0)) {
		errno = stream->stream_errno;
		return -1;
	}

	i_assert(!stream->real_stream->finished);
	ret = stream->real_stream->write_at(stream->real_stream,
					    data, size, offset);
	if (ret > 0)
		stream->real_stream->last_write_timeval = ioloop_timeval;
	else if (unlikely(ret < 0)) {
		i_assert(stream->stream_errno != 0);
		errno = stream->stream_errno;
	}

	return ret;
}

void o_stream_get_last_write_time(struct ostream *stream, struct timeval *tv_r)
{
	*tv_r = stream->real_stream->last_write_timeval;
}

enum ostream_send_istream_result
io_stream_copy(struct ostream *outstream, struct istream *instream)
{
	struct const_iovec iov;
	const unsigned char *data;
	ssize_t ret;

	while (i_stream_read_more(instream, &data, &iov.iov_len) > 0) {
		iov.iov_base = data;
		if ((ret = o_stream_sendv(outstream, &iov, 1)) < 0)
			return OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT;
		else if (ret == 0)
			return OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT;
		i_stream_skip(instream, ret);
	}

	if (instream->stream_errno != 0)
		return OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT;
	if (i_stream_have_bytes_left(instream))
		return OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT;
	return OSTREAM_SEND_ISTREAM_RESULT_FINISHED;
}

void o_stream_switch_ioloop_to(struct ostream *stream, struct ioloop *ioloop)
{
	struct ostream_private *_stream = stream->real_stream;

	io_stream_switch_ioloop_to(&_stream->iostream, ioloop);

	_stream->switch_ioloop_to(_stream, ioloop);
}

void o_stream_switch_ioloop(struct ostream *stream)
{
	o_stream_switch_ioloop_to(stream, current_ioloop);
}

static void o_stream_default_close(struct iostream_private *stream,
				   bool close_parent)
{
	struct ostream_private *_stream = (struct ostream_private *)stream;

	(void)o_stream_flush(&_stream->ostream);
	if (close_parent)
		o_stream_close(_stream->parent);
}

static void o_stream_default_destroy(struct iostream_private *stream)
{
	struct ostream_private *_stream = (struct ostream_private *)stream;

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
		_stream->last_errors_not_checked = TRUE;

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

int o_stream_flush_parent(struct ostream_private *_stream)
{
	int ret;

	i_assert(_stream->parent != NULL);

	if (!_stream->finished || !_stream->finish_also_parent ||
	    !_stream->parent->real_stream->finish_via_child)
		ret = o_stream_flush(_stream->parent);
	else
		ret = o_stream_finish(_stream->parent);
	if (ret < 0)
		o_stream_copy_error_from_parent(_stream);
	return ret;
}

static int o_stream_default_flush(struct ostream_private *_stream)
{
	if (_stream->parent == NULL)
		return 1;

	return o_stream_flush_parent(_stream);
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
o_stream_default_get_buffer_used_size(const struct ostream_private *_stream)
{
	if (_stream->parent == NULL)
		return 0;
	else
		return o_stream_get_buffer_used_size(_stream->parent);
}

static size_t
o_stream_default_get_buffer_avail_size(const struct ostream_private *_stream)
{
	/* This default implementation assumes that the returned buffer size is
	   between 0..max_buffer_size. There's no assert though, in case the
	   max_buffer_size changes. */
	size_t used = o_stream_get_buffer_used_size(&_stream->ostream);

	return _stream->max_buffer_size <= used ? 0 :
		_stream->max_buffer_size - used;
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

static enum ostream_send_istream_result
o_stream_default_send_istream(struct ostream_private *outstream,
			      struct istream *instream)
{
	return io_stream_copy(&outstream->ostream, instream);
}

static void
o_stream_default_switch_ioloop_to(struct ostream_private *_stream,
				  struct ioloop *ioloop)
{
	if (_stream->parent != NULL)
		o_stream_switch_ioloop_to(_stream->parent, ioloop);
}

struct ostream *
o_stream_create(struct ostream_private *_stream, struct ostream *parent, int fd)
{
	_stream->finish_also_parent = TRUE;
	_stream->finish_via_child = TRUE;
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
	if (_stream->get_buffer_used_size == NULL)
		_stream->get_buffer_used_size =
			o_stream_default_get_buffer_used_size;
	if (_stream->get_buffer_avail_size == NULL) {
		_stream->get_buffer_avail_size =
			o_stream_default_get_buffer_avail_size;
	}
	if (_stream->seek == NULL)
		_stream->seek = o_stream_default_seek;
	if (_stream->sendv == NULL)
		_stream->sendv = o_stream_default_sendv;
	if (_stream->write_at == NULL)
		_stream->write_at = o_stream_default_write_at;
	if (_stream->send_istream == NULL)
		_stream->send_istream = o_stream_default_send_istream;
	if (_stream->switch_ioloop_to == NULL)
		_stream->switch_ioloop_to = o_stream_default_switch_ioloop_to;

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
