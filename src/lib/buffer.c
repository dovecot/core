/* Copyright (c) 2002-2003 Timo Sirainen */

/* @UNSAFE: whole file */

#include "lib.h"
#include "buffer.h"

struct real_buffer {
	/* public: */
	const unsigned char *r_buffer;
	size_t used;

	/* private: */
	unsigned char *w_buffer;
	size_t alloc, max_alloc;

	pool_t pool;

	unsigned int alloced:1;
	unsigned int hard:1;
};

static void buffer_alloc(struct real_buffer *buf, size_t size)
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

static int buffer_check_read(const struct real_buffer *buf,
			     size_t *pos, size_t *data_size)
{
	size_t max_size;

	if (*pos >= buf->used)
		return FALSE;

	max_size = buf->used - *pos;
	if (*data_size > max_size)
		*data_size = max_size;
	return TRUE;
}

static inline int
buffer_check_limits(struct real_buffer *buf, size_t pos, size_t *data_size,
		    int accept_partial)
{
	size_t new_size, alloc_size;

	/* make sure we're within our limits */
	if (pos >= buf->max_alloc ||
	    buf->max_alloc - pos < *data_size) {
		if (buf->hard) {
			i_panic("Buffer full (%"PRIuSIZE_T" > "
				"%"PRIuSIZE_T")", pos + *data_size,
				buf->max_alloc);
		}

		if (!accept_partial || pos >= buf->max_alloc)
			return FALSE;

		*data_size = buf->max_alloc - pos;
	}
	new_size = pos + *data_size;

	/* see if we need to grow the buffer */
	if (new_size > buf->alloc) {
		alloc_size = nearest_power(new_size);
		if (alloc_size > buf->max_alloc)
			alloc_size = buf->max_alloc;

		if (alloc_size != buf->alloc)
			buffer_alloc(buf, alloc_size);
	}

	if (new_size > buf->used)
		buf->used = new_size;
	return TRUE;
}

buffer_t *buffer_create_static(pool_t pool, size_t size)
{
	struct real_buffer *buf;

	buf = p_new(pool, struct real_buffer, 1);
	buf->pool = pool;
	buf->max_alloc = size;
	buffer_alloc(buf, size);
	return (buffer_t *)buf;
}

buffer_t *buffer_create_static_hard(pool_t pool, size_t size)
{
	buffer_t *buf;

	buf = buffer_create_static(pool, size);
	((struct real_buffer *)buf)->hard = TRUE;
	return buf;
}

buffer_t *buffer_create_data(pool_t pool, void *data, size_t size)
{
	struct real_buffer *buf;

	buf = p_new(pool, struct real_buffer, 1);
	buf->pool = pool;
	buf->alloc = buf->max_alloc = size;
	buf->r_buffer = buf->w_buffer = data;
	return (buffer_t *)buf;
}

buffer_t *buffer_create_const_data(pool_t pool, const void *data, size_t size)
{
	struct real_buffer *buf;

	buf = p_new(pool, struct real_buffer, 1);
	buf->pool = pool;
	buf->used = buf->alloc = buf->max_alloc = size;
	buf->r_buffer = data;
	return (buffer_t *)buf;
}

buffer_t *buffer_create_dynamic(pool_t pool, size_t init_size, size_t max_size)
{
	struct real_buffer *buf;

	buf = p_new(pool, struct real_buffer, 1);
	buf->pool = pool;
	buf->max_alloc = max_size;
	buffer_alloc(buf, init_size);
	return (buffer_t *)buf;
}

void buffer_free(buffer_t *_buf)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	if (buf->alloced)
		p_free(buf->pool, buf->w_buffer);
	p_free(buf->pool, buf);
}

void *buffer_free_without_data(buffer_t *_buf)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;
	void *data;

	data = buf->w_buffer;
	p_free(buf->pool, buf);
	return data;
}

size_t buffer_write(buffer_t *_buf, size_t pos,
		    const void *data, size_t data_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	if (!buffer_check_limits(buf, pos, &data_size, TRUE))
		return 0;

	memcpy(buf->w_buffer + pos, data, data_size);
	return data_size;
}

size_t buffer_append(buffer_t *_buf, const void *data, size_t data_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	if (!buffer_check_limits(buf, buf->used, &data_size, TRUE))
		return 0;

	memcpy(buf->w_buffer + buf->used, data, data_size);
	return data_size;
}

size_t buffer_append_c(buffer_t *buf, unsigned char chr)
{
	return buffer_append(buf, &chr, 1);
}

size_t buffer_insert(buffer_t *_buf, size_t pos,
		     const void *data, size_t data_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;
	size_t move_size, size;

	if (pos >= buf->used)
		return buffer_write(_buf, pos, data, data_size);

	/* move_size == number of bytes we have to move forward to make space */
	move_size = buf->used - pos;

	/* size == number of bytes we want to modify after pos */
	if (data_size < (size_t)-1 - move_size)
		size = data_size + move_size;
	else
		size = (size_t)-1;

	if (!buffer_check_limits(buf, pos, &size, TRUE))
		return 0;

	i_assert(size >= move_size);
	size -= move_size;
	/* size == number of bytes we actually inserted. data_size usually. */

	memmove(buf->w_buffer + pos + size, buf->w_buffer + pos, move_size);
	memcpy(buf->w_buffer + pos, data, size);
	return size;
}

size_t buffer_delete(buffer_t *_buf, size_t pos, size_t size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;
	size_t end_size;

	if (pos >= buf->used)
		return 0;
	end_size = buf->used - pos;

	if (size < end_size) {
		/* delete from between */
		end_size -= size;
		memmove(buf->w_buffer + pos,
			buf->w_buffer + pos + size, end_size);
	} else {
		/* delete the rest of the buffer */
		size = end_size;
		end_size = 0;
	}

	buffer_set_used_size(_buf, pos + end_size);
	return size;
}

size_t buffer_copy(buffer_t *_dest, size_t dest_pos,
		   const buffer_t *_src, size_t src_pos, size_t copy_size)
{
	struct real_buffer *dest = (struct real_buffer *)_dest;
	struct real_buffer *src = (struct real_buffer *)_src;

	if (!buffer_check_read(src, &src_pos, &copy_size))
		return 0;

	if (!buffer_check_limits(dest, dest_pos, &copy_size, TRUE))
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
	return buffer_copy(dest, dest->used, src, src_pos, copy_size);
}

void *buffer_get_space_unsafe(buffer_t *_buf, size_t pos, size_t size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	if (!buffer_check_limits(buf, pos, &size, FALSE))
		return NULL;

	return buf->w_buffer + pos;
}

void *buffer_append_space_unsafe(buffer_t *buf, size_t size)
{
	return buffer_get_space_unsafe(buf, buf->used, size);
}

void *buffer_get_modifyable_data(const buffer_t *_buf, size_t *used_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	if (used_size != NULL)
		*used_size = buf->used;
	return buf->w_buffer;
}

void buffer_set_used_size(buffer_t *_buf, size_t used_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	i_assert(used_size <= buf->alloc);

	buf->used = used_size;
}

size_t buffer_get_size(const buffer_t *_buf)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	return buf->alloc;
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

	i_assert(data[0] == '!');
	i_assert(data[sizeof(data)-1] == '!');
	return 0;
}
#endif
