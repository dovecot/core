/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

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

	bool alloced:1;
	bool dynamic:1;
};
typedef int buffer_check_sizes[COMPILE_ERROR_IF_TRUE(sizeof(struct real_buffer) > sizeof(buffer_t)) ?1:1];

static void buffer_alloc(struct real_buffer *buf, size_t size)
{
	i_assert(buf->w_buffer == NULL || buf->alloced);

	if (size == buf->alloc)
		return;

	i_assert(size > buf->alloc);

	if (buf->w_buffer == NULL)
		buf->w_buffer = p_malloc(buf->pool, size);
	else
		buf->w_buffer = p_realloc(buf->pool, buf->w_buffer, buf->alloc, size);
	buf->alloc = size;

	buf->r_buffer = buf->w_buffer;
	buf->alloced = TRUE;
}

static inline void
buffer_check_limits(struct real_buffer *buf, size_t pos, size_t data_size)
{
	unsigned int extra;
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

	/* always keep +1 byte allocated available in case str_c() is called
	   for this buffer. this is mainly for cases where the buffer is
	   allocated from data stack, and str_c() is called in a separate stack
	   frame. */
	extra = buf->dynamic ? 1 : 0;
	if (new_size + extra > buf->alloc) {
		if (unlikely(!buf->dynamic)) {
			i_panic("Buffer full (%"PRIuSIZE_T" > %"PRIuSIZE_T", "
				"pool %s)", pos + data_size, buf->alloc,
				buf->pool == NULL ? "<none>" :
				pool_get_name(buf->pool));
		}

		buffer_alloc(buf, pool_get_exp_grown_size(buf->pool, buf->alloc,
							  new_size + extra));
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
	i_assert(buf->w_buffer != NULL);
}

#undef buffer_create_from_data
void buffer_create_from_data(buffer_t *buffer, void *data, size_t size)
{
	struct real_buffer *buf;

	i_assert(sizeof(*buffer) >= sizeof(struct real_buffer));

	buf = (struct real_buffer *)buffer;
	i_zero(buf);
	buf->alloc = size;
	buf->r_buffer = buf->w_buffer = data;
	/* clear the whole memory area. unnecessary usually, but if the
	   buffer is used by e.g. str_c() it tries to access uninitialized
	   memory */
	memset(data, 0, size);
}

#undef buffer_create_from_const_data
void buffer_create_from_const_data(buffer_t *buffer,
				   const void *data, size_t size)
{
	struct real_buffer *buf;

	i_assert(sizeof(*buffer) >= sizeof(struct real_buffer));

	buf = (struct real_buffer *)buffer;
	i_zero(buf);

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
	/* buffer_alloc() reserves +1 for str_c() NIL, so add +1 here to
	   init_size so we can actually write that much to the buffer without
	   realloc */
	buffer_alloc(buf, init_size+1);
	return (buffer_t *)buf;
}

void buffer_free(buffer_t **_buf)
{
	struct real_buffer *buf = (struct real_buffer *)*_buf;

	if (buf == NULL)
		return;

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

void buffer_write(buffer_t *_buf, size_t pos,
		  const void *data, size_t data_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;

	buffer_check_limits(buf, pos, data_size);
	if (data_size > 0)
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

void buffer_replace(buffer_t *_buf, size_t pos, size_t size,
		    const void *data, size_t data_size)
{
	struct real_buffer *buf = (struct real_buffer *)_buf;
	size_t end_size;

	if (pos >= buf->used) {
		buffer_write(_buf, pos, data, data_size);
		return;
	}
	end_size = buf->used - pos;

	if (size < end_size) {
		end_size -= size;
		if (data_size == 0) {
			/* delete from between */
			memmove(buf->w_buffer + pos,
				buf->w_buffer + pos + size, end_size);
		} else {
			/* insert */
			buffer_copy(_buf, pos + data_size, _buf, pos + size,
				    (size_t)-1);
			memcpy(buf->w_buffer + pos, data, data_size);
		}
	} else {
		/* overwrite the end */
		end_size = 0;
		buffer_write(_buf, pos, data, data_size);
	}

	buffer_set_used_size(_buf, pos + data_size + end_size);
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
	i_assert(src->r_buffer != NULL);

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
	i_assert(buf->used == 0 || buf->w_buffer != NULL);
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

size_t buffer_get_writable_size(const buffer_t *_buf)
{
	const struct real_buffer *buf = (const struct real_buffer *)_buf;

	if (!buf->dynamic || buf->alloc == 0)
		return buf->alloc;

	/* we reserve +1 for str_c() NUL in buffer_check_limits(), so don't
	   include that in our return value. otherwise the caller might
	   increase the buffer's alloc size unnecessarily when it just wants
	   to access the entire buffer. */
	return buf->alloc-1;
}

size_t buffer_get_avail_size(const buffer_t *_buf)
{
	const struct real_buffer *buf = (const struct real_buffer *)_buf;

	i_assert(buf->alloc >= buf->used);
	return ((buf->dynamic ? SIZE_MAX : buf->alloc) - buf->used);
}

bool buffer_cmp(const buffer_t *buf1, const buffer_t *buf2)
{
	if (buf1->used != buf2->used)
		return FALSE;
	if (buf1->used == 0)
		return TRUE;

	return memcmp(buf1->data, buf2->data, buf1->used) == 0;
}

void buffer_verify_pool(buffer_t *_buf)
{
	const struct real_buffer *buf = (const struct real_buffer *)_buf;
	void *ret;

	if (buf->pool != NULL && buf->pool->datastack_pool && buf->alloc > 0) {
		/* this doesn't really do anything except verify the
		   stack frame */
		ret = p_realloc(buf->pool, buf->w_buffer,
				buf->alloc, buf->alloc);
		i_assert(ret == buf->w_buffer);
	}
}

void buffer_truncate_rshift_bits(buffer_t *buf, size_t bits)
{
	/* no-op if it's shorten than bits in any case.. */
	if (buf->used * 8 < bits) return;

	if (bits > 0) {
		/* truncate it to closest byte boundary */
		size_t bytes = ((bits + 7) & -8U)/8;
		/* remaining bits */
		bits = bits % 8;
		buffer_set_used_size(buf, I_MIN(bytes, buf->used));
		unsigned char *ptr = buffer_get_modifiable_data(buf, &bytes);
		/* right shift over byte array */
		if (bits > 0) {
			for(size_t i=bytes-1;i>0;i--)
				ptr[i] = (ptr[i]>>(8-bits)) +
					 ((ptr[i-1]&(0xff>>(bits)))<<bits);
			ptr[0] = ptr[0]>>(8-bits);
		}
	} else {
		buffer_set_used_size(buf, 0);
	}
}

