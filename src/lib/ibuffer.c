/*
   ibuffer.c : Input buffer handling

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
#include "ibuffer-internal.h"

void i_buffer_ref(IBuffer *buf)
{
	_io_buffer_ref(buf->real_buffer);
}

void i_buffer_unref(IBuffer *buf)
{
	_io_buffer_unref(buf->real_buffer);
}

int i_buffer_get_fd(IBuffer *buf)
{
	_IBuffer *_buf = buf->real_buffer;

	return _buf->fd;
}

void i_buffer_close(IBuffer *buf)
{
	_io_buffer_close(buf->real_buffer);
	buf->closed = TRUE;
}

void i_buffer_set_max_size(IBuffer *buf, size_t max_size)
{
	_io_buffer_set_max_size(buf->real_buffer, max_size);
}

void i_buffer_set_blocking(IBuffer *buf, int timeout_msecs,
			   void (*timeout_func)(void *), void *context)
{
	_io_buffer_set_blocking(buf->real_buffer, timeout_msecs,
				timeout_func, context);
}

void i_buffer_set_start_offset(IBuffer *buf, uoff_t offset)
{
	_IBuffer *_buf = buf->real_buffer;
	off_t diff;

	i_assert(buf->v_size == 0 || offset <= buf->start_offset + buf->v_size);

	if (offset == buf->start_offset)
		return;

	diff = (off_t)buf->start_offset - (off_t)offset;
	buf->start_offset = offset;
	buf->v_offset += diff;
	if (buf->v_size != 0) {
		buf->v_size += diff;
		buf->v_limit += diff;
	}

	/* reset buffer data */
	_buf->skip = _buf->pos = _buf->cr_lookup_pos = 0;
}

void i_buffer_set_read_limit(IBuffer *buf, uoff_t v_offset)
{
	_IBuffer *_buf = buf->real_buffer;

	i_assert(buf->v_size == 0 || v_offset <= buf->v_size);

	if (v_offset == 0)
		buf->v_limit = buf->v_size;
	else {
		i_assert(v_offset >= buf->v_offset);

		buf->v_limit = v_offset;
		if (_buf->pos > v_offset - buf->v_offset + _buf->skip)
			_buf->pos = v_offset - buf->v_offset + _buf->skip;
	}
}

ssize_t i_buffer_read(IBuffer *buf)
{
	_IBuffer *_buf = buf->real_buffer;

	if (buf->closed)
		return -1;

	return _buf->read(_buf);
}

void i_buffer_skip(IBuffer *buf, uoff_t count)
{
	_IBuffer *_buf = buf->real_buffer;
	size_t data_size;

	i_assert(buf->v_size == 0 || buf->v_offset + count <= buf->v_size);

	if (count <= _buf->pos - _buf->skip) {
		buf->v_offset += count;
		_buf->skip += count;
		return;
	}

	if (buf->closed)
		return;

	data_size = _buf->pos - _buf->skip;
	_buf->skip = _buf->pos;

	count -= data_size;
	buf->v_offset += data_size;

	_buf->skip_count(_buf, count);
}

void i_buffer_seek(IBuffer *buf, uoff_t v_offset)
{
	_IBuffer *_buf = buf->real_buffer;

	i_assert(v_offset <= buf->v_size);

	if (buf->closed)
		return;

	_buf->seek(_buf, v_offset);
}

char *i_buffer_next_line(IBuffer *buf)
{
	_IBuffer *_buf = buf->real_buffer;
	char *ret_buf;
        size_t i;

        i_assert(buf != NULL);

	if (_buf->skip >= _buf->pos)
		return NULL;

	if (_buf->w_buffer == NULL) {
		i_error("i_buffer_next_line() called for unmodifyable buffer");
		return NULL;
	}

	ret_buf = NULL;
	for (i = _buf->cr_lookup_pos; i < _buf->pos; i++) {
		if (_buf->buffer[i] == 10) {
			/* got it */
			if (i > 0 && _buf->buffer[i-1] == '\r')
				_buf->w_buffer[i-1] = '\0';
			else
				_buf->w_buffer[i] = '\0';
			ret_buf = (char *) _buf->buffer + _buf->skip;

			i++;
			buf->v_offset += i - _buf->skip;
			_buf->skip = i;
                        break;
		}
	}

	_buf->cr_lookup_pos = i;
        return ret_buf;
}

const unsigned char *i_buffer_get_data(IBuffer *buf, size_t *size)
{
	_IBuffer *_buf = buf->real_buffer;

	if (_buf->skip >= _buf->pos) {
		*size = 0;
		return NULL;
	}

        *size = _buf->pos - _buf->skip;
        return _buf->buffer + _buf->skip;
}

int i_buffer_read_data(IBuffer *buf, const unsigned char **data,
		       size_t *size, size_t threshold)
{
	_IBuffer *_buf = buf->real_buffer;
	ssize_t ret = 0;

	while (_buf->pos - _buf->skip <= threshold) {
		/* we need more data */
		ret = _buf->read(_buf);
		if (ret < 0)
			break;
	}

	*data = i_buffer_get_data(buf, size);
	return *size > threshold ? 1 :
		ret == -2 ? -2 :
		*size > 0 ? 0 : -1;
}

IBuffer *_i_buffer_create(_IBuffer *_buf, Pool pool, int fd,
			  uoff_t start_offset, uoff_t v_size)
{
	_buf->fd = fd;
	_buf->ibuffer.start_offset = start_offset;
	_buf->ibuffer.v_size = v_size;
	_buf->ibuffer.v_limit = v_size;
	_buf->ibuffer.real_buffer = _buf;

	_io_buffer_init(pool, &_buf->iobuf);
	return &_buf->ibuffer;
}
