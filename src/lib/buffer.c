/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "buffer.h"

struct real_buffer {
	/* public: */
	const unsigned char *r_buffer;
	size_t used;

	/* private: */
	unsigned char *w_buffer;
	size_t dirty, alloc;

	pool_t pool;

	unsigned int alloced:1;
	unsigned int dynamic:1;
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

static inline void
buffer_check_limits(struct real_buffer *buf, size_t pos, size_t data_size)
{
	size_t new_size;

	if (unlikely((size_t)-1 - pos < data_size)) {
		i_panic("Buffer write out of range (%"PRIuSIZE_T
			" + %"PRIuSIZE_T")", pos, data_size);
	}
	new_size = pos + data_size;

	if (new_size > buf->used && buf->used < buf->dirty) {
		/* clear used..dirty area */
		size_t max = I_MIN(I_MIN(buf->alloc, buf->dirty), new_size);

		memset(buf->w_buffer + buf->used, 0, max - buf->used);
	}
	if (new_size > buf->alloc) {
		if (unlikely(!buf->dynamic)) {
			i_panic("Buffer full (%"PRIuSIZE_T" > %"PRIuSIZE_T", "
				"pool %s)", pos + data_size, buf->alloc,
				buf->pool == NULL ? "<none>" :
				pool_get_name(buf->pool));
		}

		buffer_alloc(buf, pool_get_exp_grown_size(buf->pool, buf->alloc,
							  new_size));
	}
#if 0
	else if (new_size > buf->used && buf->alloced &&
		 !buf->pool->alloconly_pool && !buf->pool->datastack_pool) {
		void *new_buf;

		/* buffer's size increased: move the buffer's memory elsewhere.
		   this should help catch bugs where old pointers are tried to
		   be used to access the buffer's memory */
		new_buf = p_malloc(buf->pool, buf->alloc);
		memcpy(new_buf, buf->w_buffer, buf->alloc);
		p_free(buf->pool, buf->w_buffer);

		buf->w_buffer = new_buf;
		buf->r_buffer = new_buf;
	}
#endif

	if (new_size > buf->used)
		buf->used = new_size;
	i_assert(buf->used <= buf->alloc);
}

void buffer_create_data(buffer_t *buffer, void *data, size_t size)
{
	struct real_buffer *buf;

	i_assert(sizeof(*buffer) >= sizeof(struct real_buffer));

	buf = (struct real_buffer *)buffer;
	memset(buf, 0, sizeof(*buf));
	buf->alloc = size;
	buf->r_buffer = buf->w_buffer = data;
}

void buffer_create_const_data(buffer_t *buffer, const void *data, size_t size)
{
	struct real_buffer *buf;

	i_assert(sizeof(*buffer) >= sizeof(struct real_buffer));

	buf = (struct real_buffer *)buffer;
	memset(buf, 0, sizeof(*buf));

	buf->used = buf->alloc = size;
	buf->r_buffer = data;
	i_assert(buf->w_buffer == NULL);
}

buffer_t *buffer_create_dynamic(pool_t pool, size_t init_size)
{
	struct real_buffer *buf;

	buf = p_new(pool, struct real_buffer, 1);
	buf->pool = pool;
	buf->dynamic = TRUE;
	buffer_alloc(buf, init_size);
	return (buffer_t *)buf;
}

void buffer_free(buffer_t **_buf)
{
	struct real_buffer *buf = (struct real_buffer *)*_buf;

	*_buf = NULL;
	if (buf->alloced)
		p_free(buf->pool, buf->w_buffer);
	if (buf->pool != NULL)
		p_free(buf->pool, buf);
}

void *buffer_free_without_data(buffer_t **_buf)
{
	struct real_buffer *buf = (struct real_buffer *)*_buf;
	void *data;

	*_buf = NULL;

	data = buf->w_buffer;
	p_free(buf->pool, buf);
	return data;
}

pool_t buffer_get_pool(const buffer_t *_buf)
{
	const struct real_buffer *buf = (const struct real_buffer *)_buf;

	return buf->pool;
}

void buffer_reset(buffer_t *buf)
{
	buffer_set_used_size(buf, 0);
}

void buffer_write(buffer_t *_buf, size_t pos,
		  const void *data, size_t data_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	buffer_check_limits(buf, pos, data_size);
	memcpy(buf->w_buffer + pos, data, data_size);
}

void buffer_append(buffer_t *buf, const void *data, size_t data_size)
{
	buffer_write(buf, buf->used, data, data_size);
}

void buffer_append_c(buffer_t *buf, unsigned char chr)
{
	buffer_append(buf, &chr, 1);
}

void buffer_insert(buffer_t *_buf, size_t pos,
		   const void *data, size_t data_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	if (pos >= buf->used)
		buffer_write(_buf, pos, data, data_size);
	else {
		buffer_copy(_buf, pos + data_size, _buf, pos, (size_t)-1);
		memcpy(buf->w_buffer + pos, data, data_size);
	}
}

void buffer_delete(buffer_t *_buf, size_t pos, size_t size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;
	size_t end_size;

	if (pos >= buf->used)
		return;
	end_size = buf->used - pos;

	if (size < end_size) {
		/* delete from between */
		end_size -= size;
		memmove(buf->w_buffer + pos,
			buf->w_buffer + pos + size, end_size);
	} else {
		/* delete the rest of the buffer */
		end_size = 0;
	}

	buffer_set_used_size(_buf, pos + end_size);
}

void buffer_write_zero(buffer_t *_buf, size_t pos, size_t data_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	buffer_check_limits(buf, pos, data_size);
	memset(buf->w_buffer + pos, 0, data_size);
}

void buffer_append_zero(buffer_t *buf, size_t data_size)
{
	buffer_write_zero(buf, buf->used, data_size);
}

void buffer_insert_zero(buffer_t *_buf, size_t pos, size_t data_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	if (pos >= buf->used)
		buffer_write_zero(_buf, pos, data_size);
	else {
		buffer_copy(_buf, pos + data_size, _buf, pos, (size_t)-1);
		memset(buf->w_buffer + pos, 0, data_size);
	}
}

void buffer_copy(buffer_t *_dest, size_t dest_pos,
		 const buffer_t *_src, size_t src_pos, size_t copy_size)
{
	struct real_buffer *dest = (struct real_buffer *)_dest;
	const struct real_buffer *src = (const struct real_buffer *)_src;
	size_t max_size;

	i_assert(src_pos <= src->used);

	max_size = src->used - src_pos;
	if (copy_size > max_size)
		copy_size = max_size;

	buffer_check_limits(dest, dest_pos, copy_size);
	if (src == dest) {
		memmove(dest->w_buffer + dest_pos,
			src->r_buffer + src_pos, copy_size);
	} else {
		memcpy(dest->w_buffer + dest_pos,
		       src->r_buffer + src_pos, copy_size);
	}
}

void buffer_append_buf(buffer_t *dest, const buffer_t *src,
		       size_t src_pos, size_t copy_size)
{
	buffer_copy(dest, dest->used, src, src_pos, copy_size);
}

void *buffer_get_space_unsafe(buffer_t *_buf, size_t pos, size_t size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	buffer_check_limits(buf, pos, size);
	return buf->w_buffer + pos;
}

void *buffer_append_space_unsafe(buffer_t *buf, size_t size)
{
	return buffer_get_space_unsafe(buf, buf->used, size);
}

void *buffer_get_modifiable_data(const buffer_t *_buf, size_t *used_size_r)
{
	const struct real_buffer *buf = (const struct real_buffer *)_buf;

	if (used_size_r != NULL)
		*used_size_r = buf->used;
	return buf->w_buffer;
}

void buffer_set_used_size(buffer_t *_buf, size_t used_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	i_assert(used_size <= buf->alloc);

	if (buf->used > buf->dirty)
		buf->dirty = buf->used;

	buf->used = used_size;
}

size_t buffer_get_size(const buffer_t *_buf)
{
	const struct real_buffer *buf = (const struct real_buffer *)_buf;

	return buf->alloc;
}

bool buffer_cmp(const buffer_t *buf1, const buffer_t *buf2)
{
	if (buf1->used != buf2->used)
		return FALSE;

	return memcmp(buf1->data, buf2->data, buf1->used) == 0;
}
