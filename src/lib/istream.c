/*
   istream.c : Input stream handling

    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "istream-internal.h"

void i_stream_ref(struct istream *stream)
{
	_io_stream_ref(&stream->real_stream->iostream);
}

void i_stream_unref(struct istream *stream)
{
	_io_stream_unref(&stream->real_stream->iostream);
}

int i_stream_get_fd(struct istream *stream)
{
	struct _istream *_stream = stream->real_stream;

	return _stream->fd;
}

void i_stream_close(struct istream *stream)
{
	_io_stream_close(&stream->real_stream->iostream);
	stream->closed = TRUE;
}

void i_stream_set_max_buffer_size(struct istream *stream, size_t max_size)
{
	_io_stream_set_max_buffer_size(&stream->real_stream->iostream,
				       max_size);
}

void i_stream_set_blocking(struct istream *stream, int timeout_msecs,
			   void (*timeout_cb)(void *), void *context)
{
	_io_stream_set_blocking(&stream->real_stream->iostream, timeout_msecs,
				timeout_cb, context);
}

void i_stream_set_start_offset(struct istream *stream, uoff_t offset)
{
	struct _istream *_stream = stream->real_stream;
	off_t diff;

	i_assert(stream->v_size == 0 ||
		 offset <= stream->start_offset + stream->v_size);

	if (offset == stream->start_offset)
		return;

	diff = (off_t)stream->start_offset - (off_t)offset;
	stream->start_offset = offset;
	stream->v_offset += diff;
	if (stream->v_size != 0) {
		stream->v_size += diff;
		stream->v_limit += diff;
	}

	/* reset buffer data */
	_stream->skip = _stream->pos = 0;
}

void i_stream_set_read_limit(struct istream *stream, uoff_t v_offset)
{
	struct _istream *_stream = stream->real_stream;
	uoff_t max_pos;

	i_assert(stream->v_size == 0 || v_offset <= stream->v_size);

	if (v_offset == 0)
		stream->v_limit = stream->v_size;
	else {
		i_assert(v_offset >= stream->v_offset);

		stream->v_limit = v_offset;
		max_pos = v_offset - stream->v_offset + _stream->skip;
		if (_stream->pos > max_pos)
			_stream->pos = max_pos;
	}
}

ssize_t i_stream_read(struct istream *stream)
{
	struct _istream *_stream = stream->real_stream;

	if (stream->closed)
		return -1;

	return _stream->read(_stream);
}

void i_stream_skip(struct istream *stream, uoff_t count)
{
	struct _istream *_stream = stream->real_stream;
	size_t data_size;

	i_assert(stream->v_size == 0 ||
		 stream->v_offset + count <= stream->v_size);

	if (count <= _stream->pos - _stream->skip) {
		stream->v_offset += count;
		_stream->skip += count;
		return;
	}

	if (stream->closed)
		return;

	data_size = _stream->pos - _stream->skip;
	_stream->skip = _stream->pos;

	count -= data_size;
	stream->v_offset += data_size;

	_stream->skip_count(_stream, count);
}

void i_stream_seek(struct istream *stream, uoff_t v_offset)
{
	struct _istream *_stream = stream->real_stream;

	i_assert(v_offset <= stream->v_size);

	if (stream->closed)
		return;

	_stream->seek(_stream, v_offset);
}

char *i_stream_next_line(struct istream *stream)
{
	struct _istream *_stream = stream->real_stream;
	char *ret_buf;
        size_t i;

        i_assert(stream != NULL);

	if (_stream->skip >= _stream->pos)
		return NULL;

	if (_stream->w_buffer == NULL) {
		i_error("i_stream_next_line() called for unmodifyable stream");
		return NULL;
	}

	/* @UNSAFE */
	ret_buf = NULL;
	for (i = _stream->skip; i < _stream->pos; i++) {
		if (_stream->buffer[i] == 10) {
			/* got it */
			if (i > 0 && _stream->buffer[i-1] == '\r')
				_stream->w_buffer[i-1] = '\0';
			else
				_stream->w_buffer[i] = '\0';
			ret_buf = (char *) _stream->w_buffer + _stream->skip;

			i++;
			stream->v_offset += i - _stream->skip;
			_stream->skip = i;
                        break;
		}
	}

        return ret_buf;
}

const unsigned char *i_stream_get_data(struct istream *stream, size_t *size)
{
	struct _istream *_stream = stream->real_stream;

	if (_stream->skip >= _stream->pos) {
		*size = 0;
		return NULL;
	}

        *size = _stream->pos - _stream->skip;
        return _stream->buffer + _stream->skip;
}

unsigned char *i_stream_get_modifyable_data(struct istream *stream,
					    size_t *size)
{
	struct _istream *_stream = stream->real_stream;

	if (_stream->skip >= _stream->pos || _stream->w_buffer == NULL) {
		*size = 0;
		return NULL;
	}

        *size = _stream->pos - _stream->skip;
        return _stream->w_buffer + _stream->skip;
}

int i_stream_read_data(struct istream *stream, const unsigned char **data,
		       size_t *size, size_t threshold)
{
	struct _istream *_stream = stream->real_stream;
	ssize_t ret = 0;

	while (_stream->pos - _stream->skip <= threshold) {
		/* we need more data */
		ret = _stream->read(_stream);
		if (ret < 0)
			break;
	}

	*data = i_stream_get_data(stream, size);
	return *size > threshold ? 1 :
		ret == -2 ? -2 :
		*size > 0 ? 0 : -1;
}

struct istream *_i_stream_create(struct _istream *_stream, pool_t pool, int fd,
				 uoff_t start_offset, uoff_t v_size)
{
	_stream->fd = fd;
	_stream->istream.start_offset = start_offset;
	_stream->istream.v_size = v_size;
	_stream->istream.v_limit = v_size;
	_stream->istream.real_stream = _stream;

	_io_stream_init(pool, &_stream->iostream);
	return &_stream->istream;
}
