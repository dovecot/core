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

struct _Buffer {
	Pool pool;

	const unsigned char *r_buffer;
	unsigned char *w_buffer;
	size_t used, alloc, max_alloc, limit, start_pos;

	unsigned int alloced:1;
	unsigned int readonly:1;
	unsigned int hard:1;
};

static void buffer_alloc(Buffer *buf, size_t min_size)
{
	if (min_size == 0)
		return;

	i_assert(buf->w_buffer == NULL || buf->alloced);

	buf->alloc = min_size;
	if (buf->w_buffer == NULL)
		buf->w_buffer = p_malloc(buf->pool, buf->alloc);
	else
		buf->w_buffer = p_realloc(buf->pool, buf->w_buffer, buf->alloc);
	buf->r_buffer = buf->w_buffer;
	buf->alloced = TRUE;
}

static int buffer_check_read(const Buffer *buf, size_t *pos, size_t *data_size)
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

static int buffer_check_write(Buffer *buf, size_t *pos, size_t *data_size,
			      int accept_partial)
{
	size_t max_size, new_size, alloc_size;

	if (buf->readonly)
		return FALSE;

	/* check that we don't overflow size_t */
	max_size = (size_t)-1 - *pos;
	if (buf->start_pos >= max_size)
		return FALSE;
	*pos += buf->start_pos;

	if (*data_size <= max_size)
		new_size = *pos + *data_size;
	else {
		new_size = *pos + max_size;
		if (new_size <= *pos || !accept_partial)
			return FALSE;
		*data_size = max_size;
	}

	/* see if we need to grow the buffer */
	if (new_size > buf->alloc) {
		alloc_size = nearest_power(new_size);
		if (alloc_size > buf->limit) {
			if (buf->hard) {
				i_panic("Buffer full (%"PRIuSIZE_T" > "
					"%"PRIuSIZE_T")",
					alloc_size, buf->limit);
			}

			if (!accept_partial)
				return FALSE;

			alloc_size = buf->limit;
			if (*pos >= alloc_size)
				return FALSE;

			*data_size = alloc_size - *pos;
		}

		if (new_size > alloc_size)
			new_size = alloc_size;

		if (alloc_size != buf->alloc)
			buffer_alloc(buf, alloc_size);
	}

	if (new_size > buf->used)
		buf->used = new_size;
	return TRUE;
}

Buffer *buffer_create_static(Pool pool, size_t size)
{
	Buffer *buf;

	buf = p_new(pool, Buffer, 1);
	buf->pool = pool;
	buf->max_alloc = buf->limit = size;
	buffer_alloc(buf, size);
	return buf;
}

Buffer *buffer_create_static_hard(Pool pool, size_t size)
{
	Buffer *buf;

	buf = buffer_create_static(pool, size);
	buf->hard = TRUE;
	return buf;
}

Buffer *buffer_create_data(Pool pool, void *data, size_t size)
{
	Buffer *buf;

	buf = p_new(pool, Buffer, 1);
	buf->pool = pool;
	buf->alloc = buf->max_alloc = buf->limit = size;
	buf->r_buffer = buf->w_buffer = data;
	return buf;
}

Buffer *buffer_create_const_data(Pool pool, const void *data, size_t size)
{
	Buffer *buf;

	buf = p_new(pool, Buffer, 1);
	buf->pool = pool;
	buf->used = buf->alloc = buf->max_alloc = buf->limit = size;
	buf->r_buffer = data;
	buf->readonly = TRUE;
	return buf;
}

Buffer *buffer_create_dynamic(Pool pool, size_t init_size, size_t max_size)
{
	Buffer *buf;

	buf = p_new(pool, Buffer, 1);
	buf->pool = pool;
	buf->max_alloc = buf->limit = max_size;
	buffer_alloc(buf, init_size);
	return buf;
}

void buffer_free(Buffer *buf)
{
	if (buf->alloced)
		p_free(buf->pool, buf->w_buffer);
	p_free(buf->pool, buf);
}

void *buffer_free_without_data(Buffer *buf)
{
	void *data;

	data = buf->w_buffer;
	p_free(buf->pool, buf);
	return data;
}

size_t buffer_write(Buffer *buf, size_t pos,
		    const void *data, size_t data_size)
{
	if (!buffer_check_write(buf, &pos, &data_size, TRUE))
		return 0;

	memcpy(buf->w_buffer + pos, data, data_size);
	return data_size;
}

size_t buffer_append(Buffer *buf, const void *data, size_t data_size)
{
	return buffer_write(buf, buf->used - buf->start_pos, data, data_size);
}

size_t buffer_append_c(Buffer *buf, char chr)
{
	size_t pos, data_size = 1;

	pos = buf->used - buf->start_pos;
	if (!buffer_check_write(buf, &pos, &data_size, TRUE))
		return 0;

	if (data_size == 1)
		buf->w_buffer[pos] = chr;
	return data_size;
}

size_t buffer_insert(Buffer *buf, size_t pos,
		     const void *data, size_t data_size)
{
	size_t move_size, size;

	move_size = buf->used - buf->start_pos;
	i_assert(pos <= move_size);
	move_size -= pos;

	if (data_size < (size_t)-1 - move_size)
		size = data_size + move_size;
	else
		size = (size_t)-1;

	if (!buffer_check_write(buf, &pos, &size, TRUE))
		return 0;

	i_assert(size >= move_size);
	size -= move_size;

	memmove(buf->w_buffer + pos + size, buf->w_buffer + pos, move_size);
	memcpy(buf->w_buffer + pos, data, size);
	return size;
}

size_t buffer_delete(Buffer *buf, size_t pos, size_t size)
{
	size_t end_size;

	if (buf->readonly)
		return 0;

	end_size = buf->used - buf->start_pos;
	i_assert(pos <= end_size);
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

size_t buffer_copy(Buffer *dest, size_t dest_pos,
		   const Buffer *src, size_t src_pos, size_t copy_size)
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

size_t buffer_append_buf(Buffer *dest, const Buffer *src,
			 size_t src_pos, size_t copy_size)
{
	return buffer_copy(dest, dest->used - dest->start_pos,
			   src, src_pos, copy_size);
}

void *buffer_get_space(Buffer *buf, size_t pos, size_t size)
{
	if (!buffer_check_write(buf, &pos, &size, FALSE))
		return 0;

	return buf->w_buffer + pos;
}

void *buffer_append_space(Buffer *buf, size_t size)
{
	return buffer_get_space(buf, buf->used - buf->start_pos, size);
}

const void *buffer_get_data(const Buffer *buf, size_t *used_size)
{
	if (used_size != NULL)
		*used_size = I_MIN(buf->used, buf->limit) - buf->start_pos;
	return buf->r_buffer + buf->start_pos;
}

void *buffer_get_modifyable_data(const Buffer *buf, size_t *used_size)
{
	if (used_size != NULL)
		*used_size = I_MIN(buf->used, buf->limit) - buf->start_pos;
	return buf->w_buffer + buf->start_pos;
}

void buffer_set_used_size(Buffer *buf, size_t used_size)
{
	i_assert(used_size <= I_MIN(buf->alloc, buf->limit) - buf->start_pos);

	buf->used = used_size + buf->start_pos;
}

size_t buffer_get_used_size(const Buffer *buf)
{
	return I_MIN(buf->used, buf->limit) - buf->start_pos;
}

size_t buffer_set_start_pos(Buffer *buf, size_t abs_pos)
{
	size_t old = buf->start_pos;

	i_assert(abs_pos <= I_MIN(buf->used, buf->limit));

	buf->start_pos = abs_pos;
	return old;
}

size_t buffer_get_start_pos(const Buffer *buf)
{
	return buf->start_pos;
}

size_t buffer_set_limit(Buffer *buf, size_t limit)
{
	size_t old = buf->limit;

	if (limit > (size_t)-1 - buf->start_pos)
		limit = (size_t)-1;
	else
		limit += buf->start_pos;

	buf->limit = I_MIN(limit, buf->max_alloc);
	return old;
}

size_t buffer_get_limit(const Buffer *buf)
{
	return buf->limit - buf->start_pos;
}

size_t buffer_get_size(const Buffer *buf)
{
	return buf->alloc - buf->start_pos;
}

#ifdef BUFFER_TEST
/* gcc buffer.c -o buffer liblib.a -Wall -DHAVE_CONFIG_H -DBUFFER_TEST -g */
int main(void)
{
	Buffer *buf;
	char data[12], *bufdata;
	size_t bufsize;

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

	buf = buffer_create_data(system_pool, bufdata, bufsize);
	i_assert(buffer_append(buf, "12345", 5) == 5);
	i_assert(buffer_insert(buf, 2, "123456", 6) == 5);
	i_assert(buf->used == 10);
	i_assert(memcmp(buf->r_buffer, "1212345345", 10) == 0);
	i_assert(buffer_delete(buf, 2, 5) == 5);
	i_assert(buf->used == 5);
	i_assert(memcmp(buf->r_buffer, "12345", 5) == 0);
	i_assert(buffer_delete(buf, 3, 5) == 2);
	i_assert(buf->used == 3);
	i_assert(memcmp(buf->r_buffer, "123", 3) == 0);

	i_assert(data[0] == '!');
	i_assert(data[sizeof(data)-1] == '!');
	return 0;
}
#endif
