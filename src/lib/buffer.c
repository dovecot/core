/*
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

/* @UNSAFE: whole file */

#include "lib.h"
#include "buffer.h"

struct buffer {
	pool_t pool;

	const unsigned char *r_buffer;
	unsigned char *w_buffer;

	/* buffer_set_start_pos() modifies start_pos, but internally we deal
	   only with absolute positions. buffer_check_read|write modifies
	   given position to absolute one.

	   start_pos <= used <= alloc <= max_alloc.
	   start_pos <= limit <= max_alloc */
	size_t start_pos, used, alloc, max_alloc, limit;

	unsigned int alloced:1;
	unsigned int readonly:1;
	unsigned int hard:1;
};

static void buffer_alloc(buffer_t *buf, size_t size)
{
	i_assert(buf->w_buffer == NULL || buf->alloced);

	if (size == buf->alloc)
		return;

	i_assert(size > buf->alloc);

	buf->w_buffer = p_realloc(buf->pool, buf->w_buffer, buf->alloc, size);
	buf->alloc = size;

	buf->r_buffer = buf->w_buffer;
	buf->alloced = TRUE;
}

static int buffer_check_read(const buffer_t *buf,
			     size_t *pos, size_t *data_size)
{
	size_t used_size, max_size;

	used_size = I_MIN(buf->used, buf->limit);
	if (*pos >= used_size - buf->start_pos)
		return FALSE;

	*pos += buf->start_pos;
	max_size = used_size - *pos;
	if (*data_size > max_size)
		*data_size = max_size;
	return TRUE;
}

static int buffer_check_write(buffer_t *buf, size_t *pos,
			      size_t *data_size, int accept_partial)
{
	size_t max_size, new_size, alloc_size;

	if (buf->readonly)
		return FALSE;

	/* check that we don't overflow size_t */
	if (*pos >= (size_t)-1 - buf->start_pos)
		return FALSE;
	*pos += buf->start_pos;

	max_size = (size_t)-1 - *pos;
	if (*data_size <= max_size)
		new_size = *pos + *data_size;
	else {
		if (max_size == 0 || !accept_partial)
			return FALSE;

		new_size = *pos + max_size;
		*data_size = max_size;
	}

	/* make sure we're within our limits */
	if (new_size > buf->limit) {
		if (buf->hard) {
			i_panic("Buffer full (%"PRIuSIZE_T" > "
				"%"PRIuSIZE_T")",
				new_size, buf->limit);
		}

		if (!accept_partial || *pos >= buf->limit)
			return FALSE;

		new_size = buf->limit;
		*data_size = new_size - *pos;
	}

	/* see if we need to grow the buffer */
	if (new_size > buf->alloc) {
		alloc_size = nearest_power(new_size);
		if (alloc_size > buf->limit)
			alloc_size = buf->limit;

		if (alloc_size != buf->alloc)
			buffer_alloc(buf, alloc_size);
	}

	if (new_size > buf->used)
		buf->used = new_size;
	return TRUE;
}

buffer_t *buffer_create_static(pool_t pool, size_t size)
{
	buffer_t *buf;

	buf = p_new(pool, buffer_t, 1);
	buf->pool = pool;
	buf->max_alloc = buf->limit = size;
	buffer_alloc(buf, size);
	return buf;
}

buffer_t *buffer_create_static_hard(pool_t pool, size_t size)
{
	buffer_t *buf;

	buf = buffer_create_static(pool, size);
	buf->hard = TRUE;
	return buf;
}

buffer_t *buffer_create_data(pool_t pool, void *data, size_t size)
{
	buffer_t *buf;

	buf = p_new(pool, buffer_t, 1);
	buf->pool = pool;
	buf->alloc = buf->max_alloc = buf->limit = size;
	buf->r_buffer = buf->w_buffer = data;
	return buf;
}

buffer_t *buffer_create_const_data(pool_t pool, const void *data, size_t size)
{
	buffer_t *buf;

	buf = p_new(pool, buffer_t, 1);
	buf->pool = pool;
	buf->used = buf->alloc = buf->max_alloc = buf->limit = size;
	buf->r_buffer = data;
	buf->readonly = TRUE;
	return buf;
}

buffer_t *buffer_create_dynamic(pool_t pool, size_t init_size, size_t max_size)
{
	buffer_t *buf;

	buf = p_new(pool, buffer_t, 1);
	buf->pool = pool;
	buf->max_alloc = buf->limit = max_size;
	buffer_alloc(buf, init_size);
	return buf;
}

void buffer_free(buffer_t *buf)
{
	if (buf->alloced)
		p_free(buf->pool, buf->w_buffer);
	p_free(buf->pool, buf);
}

void *buffer_free_without_data(buffer_t *buf)
{
	void *data;

	data = buf->w_buffer;
	p_free(buf->pool, buf);
	return data;
}

size_t buffer_write(buffer_t *buf, size_t pos,
		    const void *data, size_t data_size)
{
	if (!buffer_check_write(buf, &pos, &data_size, TRUE))
		return 0;

	memcpy(buf->w_buffer + pos, data, data_size);
	return data_size;
}

size_t buffer_append(buffer_t *buf, const void *data, size_t data_size)
{
	return buffer_write(buf, buf->used - buf->start_pos, data, data_size);
}

size_t buffer_append_c(buffer_t *buf, char chr)
{
	size_t pos, data_size = 1;

	pos = buf->used - buf->start_pos;
	if (!buffer_check_write(buf, &pos, &data_size, TRUE))
		return 0;

	if (data_size == 1)
		buf->w_buffer[pos] = chr;
	return data_size;
}

size_t buffer_insert(buffer_t *buf, size_t pos,
		     const void *data, size_t data_size)
{
	size_t move_size, size;

	/* move_size == number of bytes we have to move forward to make space */
	move_size = I_MIN(buf->used, buf->limit) - buf->start_pos;
	if (pos >= move_size)
		return buffer_write(buf, pos, data, data_size);
	move_size -= pos;

	/* size == number of bytes we want to modify after pos */
	if (data_size < (size_t)-1 - move_size)
		size = data_size + move_size;
	else
		size = (size_t)-1;

	if (!buffer_check_write(buf, &pos, &size, TRUE))
		return 0;

	i_assert(size >= move_size);
	size -= move_size;
	/* size == number of bytes we actually inserted. data_size usually. */

	memmove(buf->w_buffer + pos + size, buf->w_buffer + pos, move_size);
	memcpy(buf->w_buffer + pos, data, size);
	return size;
}

size_t buffer_delete(buffer_t *buf, size_t pos, size_t size)
{
	size_t end_size;

	if (buf->readonly)
		return 0;

	end_size = I_MIN(buf->used, buf->limit) - buf->start_pos;
	if (pos >= end_size)
		return 0;
	end_size -= pos;

	if (size < end_size) {
		/* delete from between */
		end_size -= size;
		memmove(buf->w_buffer + buf->start_pos + pos,
			buf->w_buffer + buf->start_pos + pos + size, end_size);
	} else {
		/* delete the rest of the buffer */
		size = end_size;
		end_size = 0;
	}

	buffer_set_used_size(buf, pos + end_size);
	return size;
}

size_t buffer_copy(buffer_t *dest, size_t dest_pos,
		   const buffer_t *src, size_t src_pos, size_t copy_size)
{
	if (!buffer_check_read(src, &src_pos, &copy_size))
		return 0;

	if (!buffer_check_write(dest, &dest_pos, &copy_size, TRUE))
		return 0;

	if (src == dest) {
		memmove(dest->w_buffer + dest_pos,
			src->r_buffer + src_pos, copy_size);
	} else {
		memcpy(dest->w_buffer + dest_pos,
		       src->r_buffer + src_pos, copy_size);
	}
	return copy_size;
}

size_t buffer_append_buf(buffer_t *dest, const buffer_t *src,
			 size_t src_pos, size_t copy_size)
{
	return buffer_copy(dest, dest->used - dest->start_pos,
			   src, src_pos, copy_size);
}

void *buffer_get_space_unsafe(buffer_t *buf, size_t pos, size_t size)
{
	if (!buffer_check_write(buf, &pos, &size, FALSE))
		return NULL;

	return buf->w_buffer + pos;
}

void *buffer_append_space_unsafe(buffer_t *buf, size_t size)
{
	return buffer_get_space_unsafe(buf, buf->used - buf->start_pos, size);
}

const void *buffer_get_data(const buffer_t *buf, size_t *used_size)
{
	if (used_size != NULL)
		*used_size = I_MIN(buf->used, buf->limit) - buf->start_pos;
	return buf->r_buffer + buf->start_pos;
}

void *buffer_get_modifyable_data(const buffer_t *buf, size_t *used_size)
{
	if (used_size != NULL)
		*used_size = I_MIN(buf->used, buf->limit) - buf->start_pos;
	return buf->w_buffer + buf->start_pos;
}

void buffer_set_used_size(buffer_t *buf, size_t used_size)
{
	i_assert(used_size <= I_MIN(buf->alloc, buf->limit) - buf->start_pos);

	buf->used = used_size + buf->start_pos;
}

size_t buffer_get_used_size(const buffer_t *buf)
{
	return I_MIN(buf->used, buf->limit) - buf->start_pos;
}

size_t buffer_set_start_pos(buffer_t *buf, size_t abs_pos)
{
	size_t old = buf->start_pos;

	i_assert(abs_pos <= I_MIN(buf->used, buf->limit));

	buf->start_pos = abs_pos;
	return old;
}

size_t buffer_get_start_pos(const buffer_t *buf)
{
	return buf->start_pos;
}

size_t buffer_set_limit(buffer_t *buf, size_t limit)
{
	size_t old = buf->limit;

	if (limit > (size_t)-1 - buf->start_pos)
		limit = (size_t)-1;
	else
		limit += buf->start_pos;

	buf->limit = I_MIN(limit, buf->max_alloc);
	return old - buf->start_pos;
}

size_t buffer_get_limit(const buffer_t *buf)
{
	return buf->limit - buf->start_pos;
}

size_t buffer_get_size(const buffer_t *buf)
{
	return buf->alloc - buf->start_pos;
}

#ifdef BUFFER_TEST
/* gcc buffer.c -o testbuffer liblib.a -Wall -DHAVE_CONFIG_H -DBUFFER_TEST -g */
int main(void)
{
	buffer_t *buf;
	char data[12], *bufdata;
	size_t bufsize;

	lib_init();

	memset(data, '!', sizeof(data));
	bufdata = data + 1;
	bufsize = sizeof(data)-2;

	buf = buffer_create_data(system_pool, bufdata, bufsize);
	i_assert(buffer_write(buf, 5, "12345", 5) == 5);
	i_assert(buf->used == 10);
	i_assert(buffer_write(buf, 6, "12345", 5) == 4);
	i_assert(buf->used == 10);

	buf = buffer_create_data(system_pool, bufdata, bufsize);
	i_assert(buffer_write(buf, 0, "1234567890", 10) == 10);
	i_assert(buffer_write(buf, 0, "12345678901", 11) == 10);
	i_assert(buffer_append(buf, "1", 1) == 0);
	i_assert(buf->used == 10);

	buf = buffer_create_data(system_pool, bufdata, bufsize);
	i_assert(buffer_append(buf, "12345", 5) == 5);
	i_assert(buf->used == 5);
	i_assert(buffer_append(buf, "123456", 6) == 5);
	i_assert(buf->used == 10);

	buf = buffer_create_data(system_pool, data, sizeof(data));
	buffer_set_used_size(buf, 1);
	buffer_set_start_pos(buf, 1);
	buffer_set_limit(buf, sizeof(data)-2);
	i_assert(buffer_append(buf, "12345", 5) == 5);
	i_assert(buffer_insert(buf, 2, "123456", 6) == 5);
	i_assert(buf->used == 11);
	i_assert(memcmp(buf->r_buffer, "!1212345345", 11) == 0);
	i_assert(buffer_delete(buf, 2, 5) == 5);
	i_assert(buf->used == 6);
	i_assert(memcmp(buf->r_buffer, "!12345", 6) == 0);
	i_assert(buffer_delete(buf, 3, 5) == 2);
	i_assert(buf->used == 4);
	i_assert(memcmp(buf->r_buffer, "!123", 4) == 0);

	i_assert(data[0] == '!');
	i_assert(data[sizeof(data)-1] == '!');
	return 0;
}
#endif
