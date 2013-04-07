/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "istream-private.h"

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
	i_stream_close_full(*stream, FALSE);
	i_stream_unref(stream);
}

void i_stream_ref(struct istream *stream)
{
	io_stream_ref(&stream->real_stream->iostream);
}

void i_stream_unref(struct istream **stream)
{
	struct istream_private *_stream = (*stream)->real_stream;

	if (_stream->iostream.refcount == 1) {
		if (_stream->line_str != NULL)
			str_free(&_stream->line_str);
	}
	io_stream_unref(&(*stream)->real_stream->iostream);
	*stream = NULL;
}

#undef i_stream_add_destroy_callback
void i_stream_add_destroy_callback(struct istream *stream,
				   istream_callback_t *callback, void *context)
{
	struct iostream_private *iostream = &stream->real_stream->iostream;
	struct iostream_destroy_callback *dc;

	if (!array_is_created(&iostream->destroy_callbacks))
		i_array_init(&iostream->destroy_callbacks, 2);
	dc = array_append_space(&iostream->destroy_callbacks);
	dc->callback = callback;
	dc->context = context;
}

void i_stream_remove_destroy_callback(struct istream *stream,
				      void (*callback)())
{
	struct iostream_private *iostream = &stream->real_stream->iostream;
	const struct iostream_destroy_callback *dcs;
	unsigned int i, count;

	dcs = array_get(&iostream->destroy_callbacks, &count);
	for (i = 0; i < count; i++) {
		if (dcs[i].callback == callback) {
			array_delete(&iostream->destroy_callbacks, i, 1);
			return;
		}
	}
	i_unreached();
}

int i_stream_get_fd(struct istream *stream)
{
	struct istream_private *_stream = stream->real_stream;

	return _stream->fd;
}

void i_stream_close(struct istream *stream)
{
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
	return stream->real_stream->max_buffer_size;
}

void i_stream_set_return_partial_line(struct istream *stream, bool set)
{
	stream->real_stream->return_nolf_line = set;
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

ssize_t i_stream_read(struct istream *stream)
{
	struct istream_private *_stream = stream->real_stream;
	size_t old_size;
	ssize_t ret;

	if (unlikely(stream->closed)) {
		errno = stream->stream_errno;
		return -1;
	}

	stream->eof = FALSE;
	stream->stream_errno = 0;

	if (_stream->parent != NULL)
		i_stream_seek(_stream->parent, _stream->parent_expected_offset);

	old_size = _stream->pos - _stream->skip;
	ret = _stream->read(_stream);
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
		break;
	}

	i_stream_update(_stream);
	return ret;
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
		if ((ret = i_stream_read(stream->parent)) == -2)
			return -2;

		stream->istream.stream_errno = stream->parent->stream_errno;
		stream->istream.eof = stream->parent->eof;
		stream->buffer = i_stream_get_data(stream->parent, &pos);
		/* check again, in case the parent stream had been seeked
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

void i_stream_skip(struct istream *stream, uoff_t count)
{
	struct istream_private *_stream = stream->real_stream;
	size_t data_size;

	data_size = _stream->pos - _stream->skip;
	if (count <= data_size) {
		/* within buffer */
		stream->v_offset += count;
		_stream->skip += count;
		return;
	}

	/* have to seek forward */
	count -= data_size;
	_stream->skip = _stream->pos;
	stream->v_offset += data_size;

	if (unlikely(stream->closed))
		return;

	stream->stream_errno = 0;
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
		if (unlikely(stream->closed))
			return;

		stream->eof = FALSE;
		_stream->seek(_stream, v_offset, FALSE);
	}
	i_stream_update(_stream);
}

void i_stream_seek_mark(struct istream *stream, uoff_t v_offset)
{
	struct istream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed))
		return;

	stream->eof = FALSE;
	_stream->seek(_stream, v_offset, TRUE);
	i_stream_update(_stream);
}

void i_stream_sync(struct istream *stream)
{
	struct istream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed))
		return;

	if (_stream->sync != NULL) {
		_stream->sync(_stream);
		i_stream_update(_stream);
	}
}

int i_stream_stat(struct istream *stream, bool exact, const struct stat **st_r)
{
	struct istream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed))
		return -1;

	if (_stream->stat(_stream, exact) < 0)
		return -1;
	*st_r = &_stream->statbuf;
	return 0;
}

int i_stream_get_size(struct istream *stream, bool exact, uoff_t *size_r)
{
	struct istream_private *_stream = stream->real_stream;

	if (unlikely(stream->closed))
		return -1;

	return _stream->get_size(_stream, exact, size_r);
}

bool i_stream_have_bytes_left(const struct istream *stream)
{
	const struct istream_private *_stream = stream->real_stream;

	return !stream->eof || _stream->skip != _stream->pos;
}

bool i_stream_is_eof(struct istream *stream)
{
	const struct istream_private *_stream = stream->real_stream;

	if (_stream->skip == _stream->pos)
		(void)i_stream_read(stream);
	return !i_stream_have_bytes_left(stream);
}

uoff_t i_stream_get_absolute_offset(struct istream *stream)
{
	return stream->real_stream->abs_start_offset + stream->v_offset;
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

	if (stream->w_buffer != NULL) {
		/* modify the buffer directly */
		stream->w_buffer[end] = '\0';
		ret = (char *)stream->w_buffer + stream->skip;
	} else {
		/* use a temporary string to return it */
		if (stream->line_str == NULL)
			stream->line_str = str_new(default_pool, 256);
		str_truncate(stream->line_str, 0);
		str_append_n(stream->line_str, stream->buffer + stream->skip,
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

	if (_stream->skip >= _stream->pos) {
		if (!unlikely(stream->closed))
			stream->stream_errno = 0;
		return NULL;
	}

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
			stream->stream_errno = ENOBUFS;
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

const unsigned char *
i_stream_get_data(const struct istream *stream, size_t *size_r)
{
	const struct istream_private *_stream = stream->real_stream;

	if (_stream->skip >= _stream->pos) {
		*size_r = 0;
		return NULL;
	}

        *size_r = _stream->pos - _stream->skip;
        return _stream->buffer + _stream->skip;
}

size_t i_stream_get_data_size(const struct istream *stream)
{
	const struct istream_private *_stream = stream->real_stream;

	if (_stream->skip >= _stream->pos)
		return 0;
	else
		return _stream->pos - _stream->skip;
}

unsigned char *i_stream_get_modifiable_data(const struct istream *stream,
					    size_t *size_r)
{
	const struct istream_private *_stream = stream->real_stream;

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
	memmove(stream->w_buffer, stream->w_buffer + stream->skip,
		stream->pos - stream->skip);
	stream->pos -= stream->skip;

	stream->skip = 0;
}

void i_stream_grow_buffer(struct istream_private *stream, size_t bytes)
{
	size_t old_size;

	i_assert(stream->max_buffer_size > 0);

	old_size = stream->buffer_size;

	stream->buffer_size = stream->pos + bytes;
	if (stream->buffer_size <= stream->init_buffer_size)
		stream->buffer_size = stream->init_buffer_size;
	else
		stream->buffer_size = nearest_power(stream->buffer_size);

	if (stream->buffer_size > stream->max_buffer_size)
		stream->buffer_size = stream->max_buffer_size;

	if (stream->buffer_size <= old_size)
		stream->buffer_size = old_size;
	else {
		stream->w_buffer = i_realloc(stream->w_buffer, old_size,
					     stream->buffer_size);
		stream->buffer = stream->w_buffer;
	}
}

bool i_stream_try_alloc(struct istream_private *stream,
			size_t wanted_size, size_t *size_r)
{
	i_assert(wanted_size > 0);

	if (wanted_size > stream->buffer_size - stream->pos) {
		if (stream->skip > 0) {
			/* remove the unused bytes from beginning of buffer */
                        i_stream_compress(stream);
		} else if (stream->max_buffer_size == 0 ||
			   stream->buffer_size < stream->max_buffer_size) {
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

void *i_stream_alloc(struct istream_private *stream, size_t size)
{
	size_t old_size, avail_size;

	i_stream_try_alloc(stream, size, &avail_size);
	if (avail_size < size) {
		old_size = stream->buffer_size;
		stream->buffer_size = nearest_power(stream->pos + size);
		stream->w_buffer = i_realloc(stream->w_buffer, old_size,
					     stream->buffer_size);
		stream->buffer = stream->w_buffer;
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

	if (close_parent && _stream->parent != NULL)
		i_stream_close(_stream->parent);
}

static void i_stream_default_destroy(struct iostream_private *stream)
{
	struct istream_private *_stream = (struct istream_private *)stream;

	i_free(_stream->w_buffer);
	if (_stream->parent != NULL)
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
		i_panic("stream doesn't support seeking backwards");

	while (stream->istream.v_offset < v_offset) {
		(void)i_stream_read(&stream->istream);

		available = stream->pos - stream->skip;
		if (available == 0) {
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

static int
i_stream_default_stat(struct istream_private *stream, bool exact)
{
	const struct stat *st;

	if (stream->parent == NULL)
		return stream->istream.stream_errno == 0 ? 0 : -1;

	if (i_stream_stat(stream->parent, exact, &st) < 0)
		return -1;
	stream->statbuf = *st;
	if (exact && !stream->stream_size_passthrough) {
		/* exact size is not known, even if parent returned something */
		stream->statbuf.st_size = -1;
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

struct istream *
i_stream_create(struct istream_private *_stream, struct istream *parent, int fd)
{
	_stream->fd = fd;
	if (parent != NULL) {
		_stream->access_counter = parent->real_stream->access_counter;
		_stream->parent = parent;
		_stream->parent_start_offset = parent->v_offset;
		_stream->parent_expected_offset = parent->v_offset;
		_stream->abs_start_offset = parent->v_offset +
			parent->real_stream->abs_start_offset;
		/* if parent stream is an istream-error, copy the error */
		_stream->istream.stream_errno = parent->stream_errno;
		_stream->istream.eof = parent->eof;
		i_stream_ref(parent);
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
	if (_stream->iostream.set_max_buffer_size == NULL) {
		_stream->iostream.set_max_buffer_size =
			i_stream_default_set_max_buffer_size;
	}
	if (_stream->init_buffer_size == 0)
		_stream->init_buffer_size = I_STREAM_MIN_SIZE;

	memset(&_stream->statbuf, 0, sizeof(_stream->statbuf));
	_stream->statbuf.st_size = -1;
	_stream->statbuf.st_atime =
		_stream->statbuf.st_mtime =
		_stream->statbuf.st_ctime = ioloop_time;

	io_stream_init(&_stream->iostream);
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
	i_stream_create(stream, NULL, -1);
	i_stream_set_name(&stream->istream, "(error)");
	return &stream->istream;
}
