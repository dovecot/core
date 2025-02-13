#ifndef BUFFER_H
#define BUFFER_H

struct buffer {
	union {
		struct {
			const void *data;
			const size_t used;
		};
		void *priv[9];
	};
};

/* WARNING: Be careful with functions that return pointers to data.
   With dynamic buffers they are valid only as long as buffer is not
   realloc()ed. You shouldn't rely on it being valid if you have modified
   buffer in any way. */

/* Create a modifiable buffer from given data. Writes past this size will
   i_panic(). */
void buffer_create_from_data(buffer_t *buffer, void *data, size_t size);
/* Create a non-modifiable buffer from given data. */
void buffer_create_from_const_data(buffer_t *buffer,
				   const void *data, size_t size);
#define buffer_create_from_data(b,d,s) \
	TYPE_CHECKS(void, \
	/* NOLINTBEGIN(bugprone-sizeof-expression) */ \
	COMPILE_ERROR_IF_TRUE(__builtin_object_size((d),1) < ((s)>0?(s):1)), \
	/* NOLINTEND(bugprone-sizeof-expression) */ \
	buffer_create_from_data((b), (d), (s)))
#define buffer_create_from_const_data(b,d,s) \
	TYPE_CHECKS(void, \
	/* NOLINTBEGIN(bugprone-sizeof-expression) */ \
	COMPILE_ERROR_IF_TRUE(__builtin_object_size((d),1) < ((s)>0?(s):1)), \
	/* NOLINTEND(bugprone-sizeof-expression) */ \
	buffer_create_from_const_data((b), (d), (s)))

/* Creates a dynamically growing buffer. Whenever write would exceed the
   current size it's grown. */
buffer_t *buffer_create_dynamic(pool_t pool, size_t init_size);
/* Create a dynamically growing buffer with a maximum size. Writes past the
   maximum size will i_panic(). Internally allow it to grow max_size+1 so
   str_c() NUL can be used. */
buffer_t *buffer_create_dynamic_max(pool_t pool, size_t init_size,
				    size_t max_size);

#define t_buffer_create(init_size) \
	buffer_create_dynamic(pool_datastack_create(), (init_size))

/* Free the memory used by buffer. Not needed if the memory is free'd
   directly from the memory pool. */
void buffer_free(buffer_t **buf);
/* Free the memory used by buffer structure, but return the buffer data
   unfree'd. */
void *buffer_free_without_data(buffer_t **buf);

/* Returns the pool buffer was created with. */
pool_t buffer_get_pool(const buffer_t *buf) ATTR_PURE;

/* Write data to buffer at specified position. If pos is beyond the buffer's
   current size, it is zero-filled up to that point (even if data_size==0). */
void buffer_write(buffer_t *buf, size_t pos,
		  const void *data, size_t data_size);
/* Append data to buffer. */
void buffer_append(buffer_t *buf, const void *data, size_t data_size);
/* Append character to buffer. */
void buffer_append_c(buffer_t *buf, unsigned char chr);

/* Insert the provided data into the buffer at position pos. If pos points past
   the current buffer size, the gap is zero-filled. */
void buffer_insert(buffer_t *buf, size_t pos,
		   const void *data, size_t data_size);
/* Delete data with the indicated size from the buffer at position pos. The
   deleted block may cross the current buffer size boundary, which is ignored.
 */
void buffer_delete(buffer_t *buf, size_t pos, size_t size);
/* Replace the data in the buffer with the indicated size at position pos with
   the provided data. This is a more optimized version of
   buffer_delete(buf, pos, size); buffer_insert(buf, pos, data, data_size); */
void buffer_replace(buffer_t *buf, size_t pos, size_t size,
		    const void *data, size_t data_size);

/* Fill buffer with zero bytes. */
void buffer_write_zero(buffer_t *buf, size_t pos, size_t data_size);
void buffer_append_zero(buffer_t *buf, size_t data_size);
void buffer_insert_zero(buffer_t *buf, size_t pos, size_t data_size);

/* Copy data from buffer to another. The buffers may be same in which case
   it's internal copying, possibly with overlapping positions (ie. memmove()
   like functionality). copy_size may be set to SIZE_MAX to copy the rest of
   the used data in buffer. */
void buffer_copy(buffer_t *dest, size_t dest_pos,
		 const buffer_t *src, size_t src_pos, size_t copy_size);
/* Append data to buffer from another. copy_size may be set to SIZE_MAX to
   copy the rest of the used data in buffer. */
void buffer_append_buf(buffer_t *dest, const buffer_t *src,
		       size_t src_pos, size_t copy_size);

/* Clone source buffer onto specified pool. Allocate extra_space extra space. */
static inline buffer_t *
buffer_clone(pool_t pool, const buffer_t *src, size_t extra_space)
{
	buffer_t *buf = buffer_create_dynamic(pool, src->used + extra_space);

	buffer_append_buf(buf, src, 0, SIZE_MAX);
	return buf;
}
/* Clone source buffer onto datastack. Allocate extra_space extra space. */
static inline buffer_t *
t_buffer_clone(const buffer_t *src, size_t extra_space)
{
	buffer_t *buf = buffer_create_dynamic(pool_datastack_create(),
					      src->used + extra_space);

	buffer_append_buf(buf, src, 0, SIZE_MAX);
	return buf;
}

/* Returns pointer to specified position in buffer. WARNING: The returned
   address may become invalid if you add more data to buffer. */
void *buffer_get_space_unsafe(buffer_t *buf, size_t pos, size_t size);
/* Increase the buffer usage by given size, and return a pointer to beginning
   of it. */
void *buffer_append_space_unsafe(buffer_t *buf, size_t size);

/* Like buffer_get_data(), but don't return it as const. Returns NULL if the
   buffer is non-modifiable. WARNING: The returned address may become invalid
   if you add more data to buffer. */
void *buffer_get_modifiable_data(const buffer_t *buf, size_t *used_size_r)
	ATTR_NULL(2);

/* Set the "used size" of buffer, ie. 0 would set the buffer empty.
   Must not be used to grow buffer. The data after the buffer's new size will
   be effectively lost, because e.g. buffer_get_space_unsafe() will zero out
   the contents. */
void buffer_set_used_size(buffer_t *buf, size_t used_size);

/* Clear the buffer. */
static inline void buffer_clear(buffer_t *buf)
{
	buffer_set_used_size(buf, 0);
}
/* Clear the buffer, but also make sure any contents is zeroed out. */
void buffer_clear_safe(buffer_t *_buf);

/* Returns the current buffer size. */
size_t buffer_get_size(const buffer_t *buf) ATTR_PURE;
/* Returns how many bytes we can write to buffer without increasing its size.
   With dynamic buffers this is buffer_get_size()-1, because the extra 1 byte
   is reserved for str_c()'s NUL. */
size_t buffer_get_writable_size(const buffer_t *buf) ATTR_PURE;
/* Returns the maximum number of bytes we can append to the buffer. If the
   buffer is dynamic, this is always near SIZE_MAX. */
size_t buffer_get_avail_size(const buffer_t *buf) ATTR_PURE;

/* Returns TRUE if buffer contents are identical. */
bool buffer_cmp(const buffer_t *buf1, const buffer_t *buf2);

/* Returns pointer to beginning of buffer data. Current used size of buffer is
   stored in used_size if it's non-NULL. */
static inline const void * ATTR_NULL(2)
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

/* Crash if buffer was allocated from data stack and stack frame has changed.
   This can be used as an assert-like check to verify that it's valid to
   increase the buffer size here, instead of crashing only randomly when the
   buffer needs to be increased. */
void buffer_verify_pool(buffer_t *buf);

/* This will truncate your byte buffer to contain at most
   given number of bits.

 1 bits:    01 00000001
 2 bits:    03 00000011
 3 bits:    07 00000111
 4 bits:    0f 00001111
 5 bits:    1f 00011111
 6 bits:    3f 00111111
 7 bits:    7f 01111111
 8 bits:    ff 11111111
 9 bits:  01ff 0000000111111111
10 bits:  03ff 0000001111111111
11 bits:  07ff 0000011111111111
12 bits:  0fff 0000111111111111
13 bits:  1fff 0001111111111111
14 bits:  3fff 0011111111111111
15 bits:  7fff 0111111111111111
16 bits:  ffff 1111111111111111

 and so forth

*/
void buffer_truncate_rshift_bits(buffer_t *buf, size_t bits);

enum buffer_append_result {
	/* Stream reached EOF successfully */
	BUFFER_APPEND_OK = 0,
	/* Error was encountered */
	BUFFER_APPEND_READ_ERROR = -1,
	/* Stream is non-blocking, call again later */
	BUFFER_APPEND_READ_MORE = -2,
	/* Stream was consumed up to max_read_size */
	BUFFER_APPEND_READ_MAX_SIZE = -3,
};

/* Attempt to fully read a stream. Since this can be a network stream, it
   can return BUFFER_APPEND_READ_MORE, which means you need to call this
   function again. It is caller's responsibility to keep track of
   max_read_size in case more reading is needed. */
enum buffer_append_result
buffer_append_full_istream(buffer_t *buf, struct istream *is, size_t max_read_size,
			   const char **error_r);

/* Attempt to fully read a file. BUFFER_APPEND_READ_MORE is never returned. */
enum buffer_append_result
buffer_append_full_file(buffer_t *buf, const char *file, size_t max_read_size,
			const char **error_r);

#endif
