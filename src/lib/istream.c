/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "memarea.h"
#include "istream-private.h"

static bool i_stream_is_buffer_invalid(const struct istream_private *stream);

void i_stream_set_name(struct istream *stream, const char *name)
{
	i_free(stream->real_stream->iostream.name);
	stream->real_stream->iostream.name = i_strdup(name);
}

const char *i_stream_get_name(struct istream *stream)
{
	while (stream->real_stream->iostream.name == NULL) {
		stream = stream->real_stream->parent;
		if (stream == NULL)
			return "";
	}
	return stream->real_stream->iostream.name;
}

static void i_stream_close_full(struct istream *stream, bool close_parents)
{
	io_stream_close(&stream->real_stream->iostream, close_parents);
	stream->closed = TRUE;

	if (stream->stream_errno == 0)
		stream->stream_errno = EPIPE;
}

void i_stream_destroy(struct istream **stream)
{
	if (*stream == NULL)
		return;

	i_stream_close_full(*stream, FALSE);
	i_stream_unref(stream);
}

void i_stream_ref(struct istream *stream)
{
	io_stream_ref(&stream->real_stream->iostream);
}

void i_stream_unref(struct istream **stream)
{
	struct istream_private *_stream;

	if (*stream == NULL)
		return;

	_stream = (*stream)->real_stream;

	if (!io_stream_unref(&_stream->iostream)) {
		str_free(&_stream->line_str);
		i_stream_snapshot_free(&_stream->prev_snapshot);
		i_stream_unref(&_stream->parent);
		io_stream_free(&_stream->iostream);
	}
	*stream = NULL;
}

#undef i_stream_add_destroy_callback
void i_stream_add_destroy_callback(struct istream *stream,
				   istream_callback_t *callback, void *context)
{
	io_stream_add_destroy_callback(&stream->real_stream->iostream,
				       callback, context);
}

void i_stream_remove_destroy_callback(struct istream *stream,
				      void (*callback)())
{
	io_stream_remove_destroy_callback(&stream->real_stream->iostream,
					  callback);
}

int i_stream_get_fd(struct istream *stream)
{
	struct istream_private *_stream = stream->real_stream;

	return _stream->fd;
}

const char *i_stream_get_error(struct istream *stream)
{
	struct istream *s;

	/* we'll only return errors for streams that have stream_errno set or
	   that have reached EOF. we might be returning unintended error
	   otherwise. */
	if (stream->stream_errno == 0)
		return stream->eof ? "EOF" : "<no error>";

	for (s = stream; s != NULL; s = s->real_stream->parent) {
		if (s->stream_errno == 0)
			break;
		if (s->real_stream->iostream.error != NULL)
			return s->real_stream->iostream.error;
	}
	return strerror(stream->stream_errno);
}

const char *i_stream_get_disconnect_reason(struct istream *stream)
{
	return io_stream_get_disconnect_reason(stream, NULL);
}

void i_stream_close(struct istream *stream)
{
	if (stream != NULL)
		i_stream_close_full(stream, TRUE);
}

void i_stream_set_init_buffer_size(struct istream *stream, size_t size)
{
	stream->real_stream->init_buffer_size = size;
}

void i_stream_set_max_buffer_size(struct istream *stream, size_t max_size)
{
	io_stream_set_max_buffer_size(&stream->real_stream->iostream, max_size);
}

size_t i_stream_get_max_buffer_size(struct istream *stream)
{
	size_t max_size = 0;

	do {
		if (max_size < stream->real_stream->max_buffer_size)
			max_size = stream->real_stream->max_buffer_size;
		stream = stream->real_stream->parent;
	} while (stream != NULL);
	return max_size;
}

void i_stream_set_return_partial_line(struct istream *stream, bool set)
{
	stream->real_stream->return_nolf_line = set;
}

void i_stream_set_persistent_buffers(struct istream *stream, bool set)
{
	do {
		stream->real_stream->nonpersistent_buffers = !set;
		stream = stream->real_stream->parent;
	} while (stream != NULL);
}

void i_stream_set_blocking(struct istream *stream, bool blocking)
{
	int prev_fd = -1;

	do {
		stream->blocking = blocking;
		if (stream->real_stream->fd != -1 &&
		    stream->real_stream->fd != prev_fd) {
			fd_set_nonblock(stream->real_stream->fd, !blocking);
			prev_fd = stream->real_stream->fd;
		}
		stream = stream->real_stream->parent;
	} while (stream != NULL);
}

static void i_stream_update(struct istream_private *stream)
{
	if (stream->parent == NULL)
		stream->access_counter++;
	else {
		stream->access_counter =
			stream->parent->real_stream->access_counter;
		stream->parent_expected_offset = stream->parent->v_offset;
	}
}

static bool snapshot_has_memarea(struct istream_snapshot *snapshot,
				 struct memarea *memarea)
{
	if (snapshot->old_memarea == memarea)
		return TRUE;
	if (snapshot->prev_snapshot != NULL)
		return snapshot_has_memarea(snapshot->prev_snapshot, memarea);
	return FALSE;
}

struct istream_snapshot *
i_stream_default_snapshot(struct istream_private *stream,
			  struct istream_snapshot *prev_snapshot)
{
	struct istream_snapshot *snapshot;

	if (stream->memarea != NULL) {
		if (prev_snapshot != NULL) {
			if (snapshot_has_memarea(prev_snapshot, stream->memarea))
				return prev_snapshot;
		}
		/* This stream has a memarea. Reference it, so we can later on
		   rollback if needed. */
		snapshot = i_new(struct istream_snapshot, 1);
		snapshot->old_memarea = stream->memarea;
		snapshot->prev_snapshot = prev_snapshot;
		memarea_ref(snapshot->old_memarea);
		return snapshot;
	}
	if (stream->parent == NULL) {
		if (stream->nonpersistent_buffers) {
			/* Assume that memarea would be used normally, but
			   now it's NULL because the buffer is empty and
			   empty buffers are freed. */
			i_assert(stream->skip == stream->pos);
			return prev_snapshot;
		}
		i_panic("%s is missing istream.snapshot() implementation",
			i_stream_get_name(&stream->istream));
	}
	struct istream_private *_parent_stream =
		stream->parent->real_stream;
	return _parent_stream->snapshot(_parent_stream, prev_snapshot);
}

void i_stream_snapshot_free(struct istream_snapshot **_snapshot)
{
	struct istream_snapshot *snapshot = *_snapshot;

	if (*_snapshot == NULL)
		return;
	*_snapshot = NULL;

	i_stream_snapshot_free(&snapshot->prev_snapshot);
	if (snapshot->old_memarea != NULL)
		memarea_unref(&snapshot->old_memarea);
	i_free(snapshot);
}

static struct istream_snapshot *
i_stream_noop_snapshot(struct istream_private *stream ATTR_UNUSED,
		       struct istream_snapshot *prev_snapshot)
{
	return prev_snapshot;
}

ssize_t i_stream_read(struct istream *stream)
{
	struct istream_private *_stream = stream->real_stream;
	ssize_t ret;
#ifdef DEBUG
	unsigned char prev_buf[4];
	const unsigned char *prev_data = _stream->buffer;
	size_t prev_skip = _stream->skip, prev_pos = _stream->pos;
	bool invalid = i_stream_is_buffer_invalid(_stream);

	i_assert(prev_skip <= prev_pos);
	if (invalid)
		;
	else if (prev_pos - prev_skip <= 4)
		memcpy(prev_buf, prev_data + prev_skip, prev_pos - prev_skip);
	else {
		memcpy(prev_buf, prev_data + prev_skip, 2);
		memcpy(prev_buf+2, prev_data + prev_pos - 2, 2);
	}
#endif

	_stream->prev_snapshot =
		_stream->snapshot(_stream, _stream->prev_snapshot);
	ret = i_stream_read_memarea(stream);
	if (ret > 0)
		i_stream_snapshot_free(&_stream->prev_snapshot);
#ifdef DEBUG
	else if (!invalid) {
		i_assert((_stream->pos - _stream->skip) == (prev_pos - prev_skip));
		if (prev_pos - prev_skip <= 4)
			i_assert(memcmp(prev_buf, prev_data + prev_skip, prev_pos - prev_skip) == 0);
		else {
			i_assert(memcmp(prev_buf, prev_data + prev_skip, 2) == 0);
			i_assert(memcmp(prev_buf+2, prev_data + prev_pos - 2, 2) == 0);
		}
	}
#endif
	return ret;
}

ssize_t i_stream_read_memarea(struct istream *stream)
{
	struct istream_private *_stream = stream->real_stream;
	size_t old_size;
	ssize_t ret;

	if (unlikely(stream->closed || stream->stream_errno != 0)) {
		stream->eof = TRUE;
		errno = stream->stream_errno;
		return -1;
	}

	stream->eof = FALSE;

	if (_stream->parent != NULL)
		i_stream_seek(_stream->parent, _stream->parent_expected_offset);

	old_size = _stream->pos - _stream->skip;
	if (_stream->pos < _stream->high_pos) {
		/* we're here because we seeked back within the read buffer. */
		ret = _stream->high_pos - _stream->pos;
		_stream->pos = _stream->high_pos;
		_stream->high_pos = 0;
	} else {
		_stream->high_pos = 0;
		ret = _stream->read(_stream);
	}
	i_assert(old_size <= _stream->pos - _stream->skip);
	switch (ret) {
	case -2:
		i_assert(_stream->skip != _stream->pos);
		break;
	case -1:
		if (stream->stream_errno != 0) {
			/* error handling should be easier if we now just
			   assume the stream is now at EOF */
			stream->eof = TRUE;
			errno = stream->stream_errno;
		} else {
			i_assert(stream->eof);
			i_assert(old_size == _stream->pos - _stream->skip);
		}
		break;
	case 0:
		i_assert(!stream->blocking);
		break;
	default:
		i_assert(ret > 0);
		i_assert(_stream->skip < _stream->pos);
		i_assert((size_t)ret+old_size == _stream->pos - _stream->skip);
		_stream->last_read_timeval = ioloop_timeval;
		break;
	}

	if (stream->stream_errno != 0) {
		/* error handling should be easier if we now just
		   assume the stream is now at EOF. Note that we could get here
		   even if read() didn't return -1, although that's a little
		   bit sloppy istream implementation. */
		stream->eof = TRUE;
	}

	i_stream_update(_stream);
	/* verify that parents' access_counters are valid. the parent's
	   i_stream_read() should guarantee this. */
	i_assert(!i_stream_is_buffer_invalid(_stream));
	return ret;
}

int i_stream_read_more_memarea(struct istream *stream,
			       const unsigned char **data_r, size_t *size_r)
{
	*data_r = i_stream_get_data(stream, size_r);
	if (*size_r > 0)
		return 1;

	int ret = i_stream_read_memarea(stream);
	*data_r = i_stream_get_data(stream, size_r);
	return ret;
}

void i_stream_get_last_read_time(struct istream *stream, struct timeval *tv_r)
{
	*tv_r = stream->real_stream->last_read_timeval;
}

ssize_t i_stream_read_copy_from_parent(struct istream *istream)
{
	struct istream_private *stream = istream->real_stream;
	size_t pos;
	ssize_t ret;

	stream->pos -= stream->skip;
	stream->skip = 0;

	stream->buffer = i_stream_get_data(stream->parent, &pos);
	if (pos > stream->pos)
		ret = 0;
	else do {
		ret = i_stream_read_memarea(stream->parent);
		stream->istream.stream_errno = stream->parent->stream_errno;
		stream->istream.eof = stream->parent->eof;
		stream->buffer = i_stream_get_data(stream->parent, &pos);
		/* check again, in case the parent stream had been seeked
		   backwards and the previous read() didn't get us far
		   enough. */
	} while (pos <= stream->pos && ret > 0);
	if (ret == -2) {
		i_stream_update(stream);
		return -2;
	}

	ret = pos > stream->pos ? (ssize_t)(pos - stream->pos) :
		(ret == 0 ? 0 : -1);
	stream->pos = pos;
	i_assert(ret != -1 || stream->istream.eof ||
		 stream->istream.stream_errno != 0);
	i_stream_update(stream);
	return ret;
}

void i_stream_free_buffer(struct istream_private *stream)
{
	if (stream->memarea != NULL) {
		memarea_unref(&stream->memarea);
		stream->w_buffer = NULL;
	} else if (stream->w_buffer != NULL) {
		i_free_and_null(stream->w_buffer);
	} else {
		/* don't know how to free it */
		return;
	}
	stream->buffer_size = 0;
}

void i_stream_skip(struct istream *stream, uoff_t count)
{
	struct istream_private *_stream = stream->real_stream;
	size_t data_size;

	data_size = _stream->pos - _stream->skip;
	if (count <= data_size) {
		/* within buffer */
		stream->v_offset += count;
		_stream->skip += count;
		if (_stream->nonpersistent_buffers &&
		    _stream->skip == _stream->pos) {
			_stream->skip = _stream->pos = 0;
			i_stream_free_buffer(_stream);
		}
		return;
	}

	/* have to seek forward */
	count -= data_size;
	_stream->skip = _stream->pos;
	stream->v_offset += data_size;

	if (unlikely(stream->closed || stream->stream_errno != 0))
		return;

	_stream->seek(_stream, stream->v_offset + count, FALSE);
}

static bool i_stream_can_optimize_seek(struct istream_private *stream)
{
	if (stream->parent == NULL)
		return TRUE;

	/* use the fast route only if the parent stream hasn't been changed */
	if (stream->access_counter !=
	    stream->parent->real_stream->access_counter)
		return FALSE;

	return i_stream_can_optimize_seek(stream->parent->real_stream);
}

void i_stream_seek(struct istream *stream, uoff_t v_offset)
{
	struct istream_private *_stream = stream->real_stream;

	if (v_offset >= stream->v_offset &&
	    i_stream_can_optimize_seek(_stream))
		i_stream_skip(stream, v_offset - stream->v_offset);
	else {
		if (unlikely(stream->closed || stream->stream_errno != 0)) {
			stream->eof = TRUE;
			return;
		}
		stream->eof = FALSE;
		_stream->seek(_stream, v_offset, FALSE);
	}
	i_stream_update(_stream);
}

void i_stream_seek_mark(struct istream *stream, uoff_t v_offset)
{
	struct istream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed || stream->stream_errno != 0))
		return;

	stream->eof = FALSE;
	_stream->seek(_stream, v_offset, TRUE);
	i_stream_update(_stream);
}

void i_stream_sync(struct istream *stream)
{
	struct istream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed || stream->stream_errno != 0))
		return;

	if (_stream->sync != NULL) {
		_stream->sync(_stream);
		i_stream_update(_stream);
	}
}

int i_stream_stat(struct istream *stream, bool exact, const struct stat **st_r)
{
	struct istream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed || stream->stream_errno != 0))
		return -1;

	if (_stream->stat(_stream, exact) < 0) {
		stream->eof = TRUE;
		return -1;
	}
	*st_r = &_stream->statbuf;
	return 0;
}

int i_stream_get_size(struct istream *stream, bool exact, uoff_t *size_r)
{
	struct istream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed || stream->stream_errno != 0))
		return -1;

	int ret;
	if ((ret = _stream->get_size(_stream, exact, size_r)) < 0)
		stream->eof = TRUE;
	return ret;
}

bool i_stream_have_bytes_left(struct istream *stream)
{
	return i_stream_get_data_size(stream) > 0 || !stream->eof;
}

bool i_stream_read_eof(struct istream *stream)
{
	if (i_stream_get_data_size(stream) == 0)
		(void)i_stream_read(stream);
	return !i_stream_have_bytes_left(stream);
}

uoff_t i_stream_get_absolute_offset(struct istream *stream)
{
	uoff_t abs_offset = stream->v_offset;
	while (stream != NULL) {
		abs_offset += stream->real_stream->start_offset;
		stream = stream->real_stream->parent;
	}
	return abs_offset;
}

static char *i_stream_next_line_finish(struct istream_private *stream, size_t i)
{
	char *ret;
	size_t end;

	if (i > 0 && stream->buffer[i-1] == '\r') {
		end = i - 1;
		stream->line_crlf = TRUE;
	} else {
		end = i;
		stream->line_crlf = FALSE;
	}

	if (stream->buffer == stream->w_buffer) {
		/* modify the buffer directly */
		stream->w_buffer[end] = '\0';
		ret = (char *)stream->w_buffer + stream->skip;
	} else {
		/* use a temporary string to return it */
		if (stream->line_str == NULL)
			stream->line_str = str_new(default_pool, 256);
		str_truncate(stream->line_str, 0);
		str_append_data(stream->line_str, stream->buffer + stream->skip,
				end - stream->skip);
		ret = str_c_modifiable(stream->line_str);
	}

	if (i < stream->pos)
		i++;
	stream->istream.v_offset += i - stream->skip;
	stream->skip = i;
	return ret;
}

static char *i_stream_last_line(struct istream_private *_stream)
{
	if (_stream->istream.eof && _stream->skip != _stream->pos &&
	    _stream->return_nolf_line) {
		/* the last line is missing LF and we want to return it. */
		return i_stream_next_line_finish(_stream, _stream->pos);
	}
	return NULL;
}

char *i_stream_next_line(struct istream *stream)
{
	struct istream_private *_stream = stream->real_stream;
	const unsigned char *pos;

	if (_stream->skip >= _stream->pos)
		return NULL;

	pos = memchr(_stream->buffer + _stream->skip, '\n',
		     _stream->pos - _stream->skip);
	if (pos != NULL) {
		return i_stream_next_line_finish(_stream,
						 pos - _stream->buffer);
	} else {
		return i_stream_last_line(_stream);
	}
}

char *i_stream_read_next_line(struct istream *stream)
{
	char *line;

	for (;;) {
		line = i_stream_next_line(stream);
		if (line != NULL)
			break;

		switch (i_stream_read(stream)) {
		case -2:
			io_stream_set_error(&stream->real_stream->iostream,
				"Line is too long (over %"PRIuSIZE_T
				" bytes at offset %"PRIuUOFF_T")",
				i_stream_get_data_size(stream), stream->v_offset);
			stream->stream_errno = errno = ENOBUFS;
			stream->eof = TRUE;
			return NULL;
		case -1:
			return i_stream_last_line(stream->real_stream);
		case 0:
			return NULL;
		}
	}
	return line;
}

bool i_stream_last_line_crlf(struct istream *stream)
{
	return stream->real_stream->line_crlf;
}

static bool i_stream_is_buffer_invalid(const struct istream_private *stream)
{
	if (stream->parent == NULL) {
		/* the buffer can't point to parent, because it doesn't exist */
		return FALSE;
	}
	if (stream->w_buffer != NULL) {
		/* we can pretty safely assume that the stream is using its
		   own private buffer, so it can never become invalid. */
		return FALSE;
	}
	if (stream->access_counter !=
	    stream->parent->real_stream->access_counter) {
		/* parent has been modified behind this stream, we can't trust
		   that our buffer is valid */
		return TRUE;
	}
	return i_stream_is_buffer_invalid(stream->parent->real_stream);
}

const unsigned char *
i_stream_get_data(struct istream *stream, size_t *size_r)
{
	struct istream_private *_stream = stream->real_stream;

	if (_stream->skip >= _stream->pos) {
		*size_r = 0;
		return uchar_empty_ptr;
	}

	if (i_stream_is_buffer_invalid(_stream)) {
		/* This stream may be using parent's buffer directly as
		   _stream->buffer, but the parent stream has already been
		   modified indirectly. This means that the buffer might no
		   longer point to where we assume it points to. So we'll
		   just return the stream as empty until it's read again.

		   It's a bit ugly to suddenly drop data from the stream that
		   was already read, but since this happens only with shared
		   parent istreams the caller is hopefully aware enough that
		   something like this might happen. The other solutions would
		   be to a) try to automatically read the data back (but we
		   can't handle errors..) or b) always copy data to stream's
		   own buffer instead of pointing to parent's buffer (but this
		   causes data copying that is nearly always unnecessary). */
		*size_r = 0;
		/* if we had already read until EOF, mark the stream again as
		   not being at the end of file. */
		if (stream->stream_errno == 0) {
			_stream->skip = _stream->pos = 0;
			stream->eof = FALSE;
		}
		return uchar_empty_ptr;
	}

        *size_r = _stream->pos - _stream->skip;
        return _stream->buffer + _stream->skip;
}

size_t i_stream_get_data_size(struct istream *stream)
{
	size_t size;

	(void)i_stream_get_data(stream, &size);
	return size;
}

unsigned char *i_stream_get_modifiable_data(struct istream *stream,
					    size_t *size_r)
{
	struct istream_private *_stream = stream->real_stream;

	if (_stream->skip >= _stream->pos || _stream->w_buffer == NULL) {
		*size_r = 0;
		return NULL;
	}

        *size_r = _stream->pos - _stream->skip;
        return _stream->w_buffer + _stream->skip;
}

int i_stream_read_data(struct istream *stream, const unsigned char **data_r,
		       size_t *size_r, size_t threshold)
{
	ssize_t ret = 0;
	bool read_more = FALSE;

	do {
		*data_r = i_stream_get_data(stream, size_r);
		if (*size_r > threshold)
			return 1;

		/* we need more data */
		ret = i_stream_read(stream);
		if (ret > 0)
			read_more = TRUE;
	} while (ret > 0);

	*data_r = i_stream_get_data(stream, size_r);
	if (ret == -2)
		return -2;

	if (ret == 0) {
		/* need to read more */
		i_assert(!stream->blocking);
		return 0;
	}
	if (stream->eof) {
		if (read_more) {
			/* we read at least some new data */
			return 0;
		}
	} else {
		i_assert(stream->stream_errno != 0);
	}
	return -1;
}

void i_stream_compress(struct istream_private *stream)
{
	i_assert(stream->memarea == NULL ||
		 memarea_get_refcount(stream->memarea) == 1);

	if (stream->skip != stream->pos) {
		memmove(stream->w_buffer, stream->w_buffer + stream->skip,
			stream->pos - stream->skip);
	}
	stream->pos -= stream->skip;

	stream->skip = 0;
}

static void i_stream_w_buffer_free(void *buf)
{
	i_free(buf);
}

static void
i_stream_w_buffer_realloc(struct istream_private *stream, size_t old_size)
{
	void *new_buffer;

	if (stream->memarea != NULL &&
	    memarea_get_refcount(stream->memarea) == 1) {
		/* Nobody else is referencing the memarea.
		   We can just reallocate it. */
		memarea_free_without_callback(&stream->memarea);
		new_buffer = i_realloc(stream->w_buffer, old_size,
				       stream->buffer_size);
	} else {
		new_buffer = i_malloc(stream->buffer_size);
		if (old_size > 0) {
			i_assert(stream->w_buffer != NULL);
			memcpy(new_buffer, stream->w_buffer, old_size);
		}
		if (stream->memarea != NULL)
			memarea_unref(&stream->memarea);
	}

	stream->w_buffer = new_buffer;
	stream->buffer = new_buffer;

	stream->memarea = memarea_init(stream->w_buffer, stream->buffer_size,
				       i_stream_w_buffer_free, new_buffer);
}

void i_stream_grow_buffer(struct istream_private *stream, size_t bytes)
{
	size_t old_size, max_size;

	old_size = stream->buffer_size;

	stream->buffer_size = stream->pos + bytes;
	if (stream->buffer_size <= stream->init_buffer_size)
		stream->buffer_size = stream->init_buffer_size;
	else
		stream->buffer_size = nearest_power(stream->buffer_size);

	max_size = i_stream_get_max_buffer_size(&stream->istream);
	i_assert(max_size > 0);
	if (stream->buffer_size > max_size)
		stream->buffer_size = max_size;

	if (stream->buffer_size <= old_size)
		stream->buffer_size = old_size;
	else
		i_stream_w_buffer_realloc(stream, old_size);
}

bool i_stream_try_alloc(struct istream_private *stream,
			size_t wanted_size, size_t *size_r)
{
	i_assert(wanted_size > 0);

	if (wanted_size > stream->buffer_size - stream->pos) {
		if (stream->skip > 0) {
			/* remove the unused bytes from beginning of buffer */
			if (stream->memarea != NULL &&
			    memarea_get_refcount(stream->memarea) > 1) {
				/* The memarea is still referenced. We can't
				   overwrite data until extra references are
				   gone. */
				i_stream_w_buffer_realloc(stream, stream->buffer_size);
			}
			i_stream_compress(stream);
		} else if (stream->buffer_size < i_stream_get_max_buffer_size(&stream->istream)) {
			/* buffer is full - grow it */
			i_stream_grow_buffer(stream, I_STREAM_MIN_SIZE);
		}
	}

	*size_r = stream->buffer_size - stream->pos;
	if (stream->try_alloc_limit > 0 &&
	    *size_r > stream->try_alloc_limit)
		*size_r = stream->try_alloc_limit;
	return *size_r > 0;
}

bool ATTR_NOWARN_UNUSED_RESULT
i_stream_try_alloc_avoid_compress(struct istream_private *stream,
				  size_t wanted_size, size_t *size_r)
{
	size_t old_skip = stream->skip;

	/* try first with skip=0, so no compression is done */
	stream->skip = 0;
	bool ret = i_stream_try_alloc(stream, wanted_size, size_r);
	stream->skip = old_skip;
	if (ret || old_skip == 0)
		return ret;
	/* it's full. try with compression. */
	return i_stream_try_alloc(stream, wanted_size, size_r);
}

void *i_stream_alloc(struct istream_private *stream, size_t size)
{
	size_t old_size, avail_size;

	i_stream_try_alloc(stream, size, &avail_size);
	if (avail_size < size) {
		old_size = stream->buffer_size;
		stream->buffer_size = nearest_power(stream->pos + size);
		i_stream_w_buffer_realloc(stream, old_size);

		i_stream_try_alloc(stream, size, &avail_size);
		i_assert(avail_size >= size);
	}
	return stream->w_buffer + stream->pos;
}

bool i_stream_add_data(struct istream *_stream, const unsigned char *data,
		       size_t size)
{
	struct istream_private *stream = _stream->real_stream;
	size_t size2;

	i_stream_try_alloc(stream, size, &size2);
	if (size > size2)
		return FALSE;

	memcpy(stream->w_buffer + stream->pos, data, size);
	stream->pos += size;
	return TRUE;
}

struct istream *i_stream_get_root_io(struct istream *stream)
{
	while (stream->real_stream->parent != NULL) {
		i_assert(stream->real_stream->io == NULL);
		stream = stream->real_stream->parent;
	}
	return stream;
}

void i_stream_set_input_pending(struct istream *stream, bool pending)
{
	if (!pending)
		return;

	stream = i_stream_get_root_io(stream);
	if (stream->real_stream->io != NULL)
		io_set_pending(stream->real_stream->io);
	else
		stream->real_stream->io_pending = TRUE;
}

void i_stream_switch_ioloop_to(struct istream *stream, struct ioloop *ioloop)
{
	io_stream_switch_ioloop_to(&stream->real_stream->iostream, ioloop);

	do {
		if (stream->real_stream->switch_ioloop_to != NULL) {
			stream->real_stream->switch_ioloop_to(
				stream->real_stream, ioloop);
		}
		stream = stream->real_stream->parent;
	} while (stream != NULL);
}

void i_stream_switch_ioloop(struct istream *stream)
{
	i_stream_switch_ioloop_to(stream, current_ioloop);
}

void i_stream_set_io(struct istream *stream, struct io *io)
{
	stream = i_stream_get_root_io(stream);

	i_assert(stream->real_stream->io == NULL);
	stream->real_stream->io = io;
	if (stream->real_stream->io_pending) {
		io_set_pending(io);
		stream->real_stream->io_pending = FALSE;
	}
}

void i_stream_unset_io(struct istream *stream, struct io *io)
{
	stream = i_stream_get_root_io(stream);

	i_assert(stream->real_stream->io == io);
	if (io_is_pending(io))
		stream->real_stream->io_pending = TRUE;
	stream->real_stream->io = NULL;
}

static void
i_stream_default_set_max_buffer_size(struct iostream_private *stream,
				     size_t max_size)
{
	struct istream_private *_stream = (struct istream_private *)stream;

	_stream->max_buffer_size = max_size;
	if (_stream->parent != NULL)
		i_stream_set_max_buffer_size(_stream->parent, max_size);
}

static void i_stream_default_close(struct iostream_private *stream,
				   bool close_parent)
{
	struct istream_private *_stream = (struct istream_private *)stream;

	if (close_parent)
		i_stream_close(_stream->parent);
}

static void i_stream_default_destroy(struct iostream_private *stream)
{
	struct istream_private *_stream = (struct istream_private *)stream;

	i_stream_free_buffer(_stream);
	i_stream_unref(&_stream->parent);
}

static void
i_stream_default_seek_seekable(struct istream_private *stream,
			       uoff_t v_offset, bool mark ATTR_UNUSED)
{
	stream->istream.v_offset = v_offset;
	stream->skip = stream->pos = 0;
}

void i_stream_default_seek_nonseekable(struct istream_private *stream,
				       uoff_t v_offset, bool mark ATTR_UNUSED)
{
	size_t available;

	if (stream->istream.v_offset > v_offset)
		i_panic("stream %s doesn't support seeking backwards",
			i_stream_get_name(&stream->istream));

	while (stream->istream.v_offset < v_offset) {
		(void)i_stream_read(&stream->istream);

		available = stream->pos - stream->skip;
		if (available == 0) {
			if (stream->istream.stream_errno != 0) {
				/* read failed */
				return;
			}
			io_stream_set_error(&stream->iostream,
				"Can't seek to offset %"PRIuUOFF_T
				", because we have data only up to offset %"
				PRIuUOFF_T" (eof=%d)", v_offset,
				stream->istream.v_offset, stream->istream.eof ? 1 : 0);
			stream->istream.stream_errno = ESPIPE;
			return;
		}
		if (available <= v_offset - stream->istream.v_offset)
			i_stream_skip(&stream->istream, available);
		else {
			i_stream_skip(&stream->istream,
				      v_offset - stream->istream.v_offset);
		}
	}
}

bool i_stream_nonseekable_try_seek(struct istream_private *stream,
				   uoff_t v_offset)
{
	uoff_t start_offset = stream->istream.v_offset - stream->skip;

	if (v_offset < start_offset) {
		/* have to seek backwards */
		i_stream_seek(stream->parent, stream->parent_start_offset);
		stream->parent_expected_offset = stream->parent_start_offset;
		stream->skip = stream->pos = 0;
		stream->istream.v_offset = 0;
		stream->high_pos = 0;
		return FALSE;
	}

	if (v_offset <= start_offset + stream->pos) {
		/* seeking backwards within what's already cached */
		stream->skip = v_offset - start_offset;
		stream->istream.v_offset = v_offset;
		stream->high_pos = stream->pos;
		stream->pos = stream->skip;
	} else {
		/* read forward */
		i_stream_default_seek_nonseekable(stream, v_offset, FALSE);
	}
	return TRUE;
}

static int
seekable_i_stream_get_size(struct istream_private *stream)
{
	if (stream->cached_stream_size == (uoff_t)-1) {
		uoff_t old_offset = stream->istream.v_offset;
		ssize_t ret;

		do {
			i_stream_skip(&stream->istream,
				i_stream_get_data_size(&stream->istream));
		} while ((ret = i_stream_read(&stream->istream)) > 0);
		i_assert(ret == -1);
		if (stream->istream.stream_errno != 0)
			return -1;

		stream->cached_stream_size = stream->istream.v_offset;
		i_stream_seek(&stream->istream, old_offset);
	}
	stream->statbuf.st_size = stream->cached_stream_size;
	return 0;
}

static int
i_stream_default_stat(struct istream_private *stream, bool exact)
{
	const struct stat *st;

	if (stream->parent == NULL)
		return stream->istream.stream_errno == 0 ? 0 : -1;

	if (i_stream_stat(stream->parent, exact, &st) < 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		return -1;
	}
	stream->statbuf = *st;
	if (exact && !stream->stream_size_passthrough) {
		/* exact size is not known, even if parent returned something */
		stream->statbuf.st_size = -1;
		if (stream->istream.seekable) {
			if (seekable_i_stream_get_size(stream) < 0)
				return -1;
		}
	} else {
		/* When exact=FALSE always return the parent stat's size, even
		   if we know the exact value. This is necessary because
		   otherwise e.g. mbox code can see two different values and
		   think that the mbox file keeps changing. */
	}
	return 0;
}

static int
i_stream_default_get_size(struct istream_private *stream,
			  bool exact, uoff_t *size_r)
{
	if (stream->stat(stream, exact) < 0)
		return -1;
	if (stream->statbuf.st_size == -1)
		return 0;

	*size_r = stream->statbuf.st_size;
	return 1;
}

void i_stream_init_parent(struct istream_private *_stream,
			  struct istream *parent)
{
	_stream->access_counter = parent->real_stream->access_counter;
	_stream->parent = parent;
	_stream->parent_start_offset = parent->v_offset;
	_stream->parent_expected_offset = parent->v_offset;
	_stream->start_offset = parent->v_offset;
	/* if parent stream is an istream-error, copy the error */
	_stream->istream.stream_errno = parent->stream_errno;
	_stream->istream.eof = parent->eof;
	i_stream_ref(parent);
}

struct istream *
i_stream_create(struct istream_private *_stream, struct istream *parent, int fd,
		enum istream_create_flag flags)
{
	bool noop_snapshot = (flags & ISTREAM_CREATE_FLAG_NOOP_SNAPSHOT) != 0;

	_stream->fd = fd;
	if (parent != NULL)
		i_stream_init_parent(_stream, parent);
	else if (_stream->memarea == NULL && !noop_snapshot) {
		/* The stream has no parent and no memarea yet. We'll assume
		   that it wants to be using memareas for the reads. */
		_stream->memarea = memarea_init_empty();
	}
	_stream->istream.real_stream = _stream;

	if (_stream->iostream.close == NULL)
		_stream->iostream.close = i_stream_default_close;
	if (_stream->iostream.destroy == NULL)
		_stream->iostream.destroy = i_stream_default_destroy;
	if (_stream->seek == NULL) {
		_stream->seek = _stream->istream.seekable ?
			i_stream_default_seek_seekable :
			i_stream_default_seek_nonseekable;
	}
	if (_stream->stat == NULL)
		_stream->stat = i_stream_default_stat;
	if (_stream->get_size == NULL)
		_stream->get_size = i_stream_default_get_size;
	if (_stream->snapshot == NULL) {
		_stream->snapshot = noop_snapshot ?
			i_stream_noop_snapshot :
			i_stream_default_snapshot;
	}
	if (_stream->iostream.set_max_buffer_size == NULL) {
		_stream->iostream.set_max_buffer_size =
			i_stream_default_set_max_buffer_size;
	}
	if (_stream->init_buffer_size == 0)
		_stream->init_buffer_size = I_STREAM_MIN_SIZE;

	i_zero(&_stream->statbuf);
	_stream->statbuf.st_size = -1;
	_stream->statbuf.st_atime =
		_stream->statbuf.st_mtime =
		_stream->statbuf.st_ctime = ioloop_time;
	_stream->cached_stream_size = (uoff_t)-1;

	io_stream_init(&_stream->iostream);

	if (_stream->istream.stream_errno != 0)
		_stream->istream.eof = TRUE;

	return &_stream->istream;
}

struct istream *i_stream_create_error(int stream_errno)
{
	struct istream_private *stream;

	stream = i_new(struct istream_private, 1);
	stream->istream.closed = TRUE;
	stream->istream.readable_fd = FALSE;
	stream->istream.blocking = TRUE;
	stream->istream.seekable = TRUE;
	stream->istream.eof = TRUE;
	stream->istream.stream_errno = stream_errno;
	i_stream_create(stream, NULL, -1, 0);
	i_stream_set_name(&stream->istream, "(error)");
	return &stream->istream;
}

struct istream *
i_stream_create_error_str(int stream_errno, const char *fmt, ...)
{
	struct istream *input;
	va_list args;

	va_start(args, fmt);
	input = i_stream_create_error(stream_errno);
	io_stream_set_verror(&input->real_stream->iostream, fmt, args);
	va_end(args);
	return input;
}
