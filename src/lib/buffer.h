#ifndef __BUFFER_H
#define __BUFFER_H

/* Create a static sized buffer. Writes past this size will simply not
   succeed. */
Buffer *buffer_create_static(Pool pool, size_t size);
/* Create a static sized buffer. Writes past this size will kill the program. */
Buffer *buffer_create_static_hard(Pool pool, size_t size);
/* Create a modifyable buffer from given data. */
Buffer *buffer_create_data(Pool pool, void *data, size_t size);
/* Create a non-modifyable buffer from given data. */
Buffer *buffer_create_const_data(Pool pool, const void *data, size_t size);
/* Creates a dynamically growing buffer. Whenever write would exceed the
   current size it's grown. */
Buffer *buffer_create_dynamic(Pool pool, size_t init_size, size_t max_size);
/* Free the memory used by buffer. Not needed if the memory is free'd
   directly from the memory pool. */
void buffer_free(Buffer *buf);
/* Free the memory used by buffer structure, but return the buffer data
   unfree'd.*/
void *buffer_free_without_data(Buffer *buf);

/* Write data to buffer at specified position, returns number of bytes
   written. */
size_t buffer_write(Buffer *buf, size_t pos,
		    const void *data, size_t data_size);
/* Append data to buffer, returns number of bytes written. */
size_t buffer_append(Buffer *buf, const void *data, size_t data_size);
/* Append character to buffer, returns 1 if written, 0 if not. */
size_t buffer_append_c(Buffer *buf, char chr);

/* Copy data from buffer to another. The buffers may be same in which case
   it's internal copying, possibly with overlapping positions (ie. memmove()
   like functionality). copy_size may be set to (size_t)-1 to copy the rest of
   the used data in buffer. Returns the number of bytes actually copied. */
size_t buffer_copy(Buffer *dest, size_t dest_pos,
		   const Buffer *src, size_t src_pos, size_t copy_size);
/* Append data to buffer from another. copy_size may be set to (size_t)-1 to
   copy the rest of the used data in buffer. */
size_t buffer_append_buf(Buffer *dest, const Buffer *src,
			 size_t src_pos, size_t copy_size);

/* Returns pointer to specified position in buffer, or NULL if there's not
   enough space. */
void *buffer_get_space(Buffer *buf, size_t pos, size_t size);
/* Increase the buffer usage by given size, and return a pointer to beginning
   of it, or NULL if there's not enough space in buffer. */
void *buffer_append_space(Buffer *buf, size_t size);

/* Returns pointer to beginning of buffer data. Current used size of buffer is
   stored in used_size if it's non-NULL. */
const void *buffer_get_data(const Buffer *buf, size_t *used_size);
/* Like buffer_get_data(), but don't return it as const. Returns NULL if the
   buffer is non-modifyable. */
void *buffer_get_modifyable_data(const Buffer *buf, size_t *used_size);

/* Set the "used size" of buffer, ie. 0 would set the buffer empty.
   Must not be used to grow buffer. */
void buffer_set_used_size(Buffer *buf, size_t used_size);
/* Returns the current used buffer size. */
size_t buffer_get_used_size(const Buffer *buf);

/* Change the buffer start position. The buffer acts as if data was removed or
   inserted to beginning. Returns the old start position. */
size_t buffer_set_start_pos(Buffer *buf, size_t abs_pos);
/* Returns the current start position. */
size_t buffer_get_start_pos(const Buffer *buf);

/* Limit buffer size temporarily. All handling is treated as if this is the
   current allocated memory size, except dynamic buffer won't be grown.
   Setting the limit to (size_t)-1 removes it. Returns the old limit. */
size_t buffer_set_limit(Buffer *buf, size_t limit);
/* Returns the current buffer limit, or (size_t)-1 if there's none. */
size_t buffer_get_limit(const Buffer *buf);

/* Returns the current buffer size. */
size_t buffer_get_size(const Buffer *buf);

#endif
