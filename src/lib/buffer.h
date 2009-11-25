#ifndef BUFFER_H
#define BUFFER_H

struct buffer {
	const void *data;
	const size_t used;
	void *priv[5];
};

/* WARNING: Be careful with functions that return pointers to data.
   With dynamic buffers they are valid only as long as buffer is not
   realloc()ed. You shouldn't rely on it being valid if you have modified
   buffer in any way. */

/* Create a modifiable buffer from given data. Writes past this size will
   i_panic(). */
void buffer_create_data(buffer_t *buffer, void *data, size_t size);
/* Create a non-modifiable buffer from given data. */
void buffer_create_const_data(buffer_t *buffer, const void *data, size_t size);
/* Creates a dynamically growing buffer. Whenever write would exceed the
   current size it's grown. */
buffer_t *buffer_create_dynamic(pool_t pool, size_t init_size);
/* Free the memory used by buffer. Not needed if the memory is free'd
   directly from the memory pool. */
void buffer_free(buffer_t **buf);
/* Free the memory used by buffer structure, but return the buffer data
   unfree'd. */
void *buffer_free_without_data(buffer_t **buf);

/* Returns the pool buffer was created with. */
pool_t buffer_get_pool(const buffer_t *buf) ATTR_PURE;

/* Reset the buffer. used size and it's contents are zeroed. */
void buffer_reset(buffer_t *buf);

/* Write data to buffer at specified position. */
void buffer_write(buffer_t *buf, size_t pos,
		  const void *data, size_t data_size);
/* Append data to buffer. */
void buffer_append(buffer_t *buf, const void *data, size_t data_size);
/* Append character to buffer. */
void buffer_append_c(buffer_t *buf, unsigned char chr);

/* Insert data to buffer. */
void buffer_insert(buffer_t *buf, size_t pos,
		   const void *data, size_t data_size);
/* Delete data from buffer. */
void buffer_delete(buffer_t *buf, size_t pos, size_t size);

/* Fill buffer with zero bytes. */
void buffer_write_zero(buffer_t *buf, size_t pos, size_t data_size);
void buffer_append_zero(buffer_t *buf, size_t data_size);
void buffer_insert_zero(buffer_t *buf, size_t pos, size_t data_size);

/* Copy data from buffer to another. The buffers may be same in which case
   it's internal copying, possibly with overlapping positions (ie. memmove()
   like functionality). copy_size may be set to (size_t)-1 to copy the rest of
   the used data in buffer. */
void buffer_copy(buffer_t *dest, size_t dest_pos,
		 const buffer_t *src, size_t src_pos, size_t copy_size);
/* Append data to buffer from another. copy_size may be set to (size_t)-1 to
   copy the rest of the used data in buffer. */
void buffer_append_buf(buffer_t *dest, const buffer_t *src,
		       size_t src_pos, size_t copy_size);

/* Returns pointer to specified position in buffer. WARNING: The returned
   address may become invalid if you add more data to buffer. */
void *buffer_get_space_unsafe(buffer_t *buf, size_t pos, size_t size);
/* Increase the buffer usage by given size, and return a pointer to beginning
   of it. */
void *buffer_append_space_unsafe(buffer_t *buf, size_t size);

/* Like buffer_get_data(), but don't return it as const. Returns NULL if the
   buffer is non-modifiable. WARNING: The returned address may become invalid
   if you add more data to buffer. */
void *buffer_get_modifiable_data(const buffer_t *buf, size_t *used_size_r);

/* Set the "used size" of buffer, ie. 0 would set the buffer empty.
   Must not be used to grow buffer. */
void buffer_set_used_size(buffer_t *buf, size_t used_size);

/* Returns the current buffer size. */
size_t buffer_get_size(const buffer_t *buf) ATTR_PURE;

/* Returns TRUE if buffer contents are identical. */
bool buffer_cmp(const buffer_t *buf1, const buffer_t *buf2);

/* Returns pointer to beginning of buffer data. Current used size of buffer is
   stored in used_size if it's non-NULL. */
static inline const void *
buffer_get_data(const buffer_t *buf, size_t *used_size_r)
{
	if (used_size_r != NULL)
		*used_size_r = buf->used;
	return buf->data;
}

/* Returns the current used buffer size. */
static inline size_t ATTR_PURE
buffer_get_used_size(const buffer_t *buf)
{
	return buf->used;
}

#endif
