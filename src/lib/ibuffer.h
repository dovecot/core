#ifndef __IBUFFER_H
#define __IBUFFER_H

struct _IBuffer {
	uoff_t start_offset;
	uoff_t v_offset, v_size, v_limit; /* relative to start_offset */

	int buf_errno;
	unsigned int closed:1;

	void *real_buffer;
};

IBuffer *i_buffer_create_file(int fd, Pool pool, size_t max_buffer_size,
			      int autoclose_fd);
IBuffer *i_buffer_create_mmap(int fd, Pool pool, size_t block_size,
			      uoff_t start_offset, uoff_t v_size,
			      int autoclose_fd);
IBuffer *i_buffer_create_from_data(Pool pool, const unsigned char *data,
				   size_t size);

/* Reference counting. References start from 1, so calling i_buffer_unref()
   destroys the buffer if i_buffer_ref() is never used. */
void i_buffer_ref(IBuffer *buf);
void i_buffer_unref(IBuffer *buf);

/* Return file descriptor for buffer, or -1 if none is available. */
int i_buffer_get_fd(IBuffer *buf);

/* Mark the buffer closed. Any reads after this will return -1. The data
   already in buffer can still be used. */
void i_buffer_close(IBuffer *buf);

/* Change the maximum size for buffer to grow. */
void i_buffer_set_max_size(IBuffer *buf, size_t max_size);
/* Change the start_offset and drop all data in buffers. Doesn't do anything
   if offset is the same as existing start_offset. */
void i_buffer_set_start_offset(IBuffer *buf, uoff_t offset);
/* Input buffer won't be read past specified offset. Giving 0 as offset
   removes the limit. The offset is  */
void i_buffer_set_read_limit(IBuffer *buf, uoff_t v_offset);
/* Makes reads blocking until at least one byte is read. timeout_func is
   called if nothing is read in specified time. Setting timeout_msecs to 0
   makes it non-blocking. This call changes non-blocking state of file
   descriptor. */
void i_buffer_set_blocking(IBuffer *buf, int timeout_msecs,
			   void (*timeout_func)(void *), void *context);

/* Returns number of bytes read if read was ok, -1 if EOF or error, -2 if the
   buffer is full. */
ssize_t i_buffer_read(IBuffer *buf);
/* Skip forward a number of bytes. Never fails, the next read tells if it
   was successful. */
void i_buffer_skip(IBuffer *buf, uoff_t count);
/* Seek to specified position from beginning of file. This works only for
   files. Returns 1 if successful, -1 if error. */
int i_buffer_seek(IBuffer *buf, uoff_t v_offset);
/* Returns the next line from input buffer, or NULL if more data is needed
   to make a full line. NOTE: modifies the data in the buffer for the \0, so
   it works only with ibuffers that allow it (currently only file). */
char *i_buffer_next_line(IBuffer *buf);
/* Returns pointer to beginning of data in buffer, or NULL if there's
   no data. */
const unsigned char *i_buffer_get_data(IBuffer *buf, size_t *size);
/* Like i_buffer_get_data(), but read it when needed. Returns 1 if more
   than threshold bytes were stored into buffer, 0 if less, -1 if error or
   EOF with no bytes in buffer or -2 if buffer is full. */
int i_buffer_read_data(IBuffer *buf, const unsigned char **data,
		       size_t *size, size_t threshold);

#endif
