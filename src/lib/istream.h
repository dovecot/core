#ifndef __ISTREAM_H
#define __ISTREAM_H

struct istream {
	uoff_t start_offset;
	uoff_t v_offset, v_size, v_limit; /* relative to start_offset */

	int stream_errno;
	unsigned int mmaped:1; /* be careful when copying data */
	unsigned int closed:1;

	struct _istream *real_stream;
};

struct istream *i_stream_create_file(int fd, pool_t pool,
				     size_t max_buffer_size, int autoclose_fd);
struct istream *i_stream_create_mmap(int fd, pool_t pool, size_t block_size,
				     uoff_t start_offset, uoff_t v_size,
				     int autoclose_fd);
struct istream *i_stream_create_from_data(pool_t pool, const void *data,
					  size_t size);

/* Reference counting. References start from 1, so calling i_stream_unref()
   destroys the stream if i_stream_ref() is never used. */
void i_stream_ref(struct istream *stream);
void i_stream_unref(struct istream *stream);

/* Return file descriptor for stream, or -1 if none is available. */
int i_stream_get_fd(struct istream *stream);

/* Mark the stream closed. Any reads after this will return -1. The data
   already read can still be used. */
void i_stream_close(struct istream *stream);

/* Change the maximum size for stream's input buffer to grow. Useful only
   for buffered streams (currently only file). */
void i_stream_set_max_buffer_size(struct istream *stream, size_t max_size);
/* Change the start_offset and drop all data in buffers. Doesn't do anything
   if offset is the same as existing start_offset. */
void i_stream_set_start_offset(struct istream *stream, uoff_t offset);
/* Stream won't be read past specified offset. Giving 0 as offset
   removes the limit. */
void i_stream_set_read_limit(struct istream *stream, uoff_t v_offset);
/* Makes reads blocking until at least one byte is read. timeout_cb is
   called if nothing is read in specified time. Setting timeout_msecs to 0
   makes it non-blocking. This call changes non-blocking state of file
   descriptor. */
void i_stream_set_blocking(struct istream *stream, int timeout_msecs,
			   void (*timeout_cb)(void *), void *context);

/* Returns number of bytes read if read was ok, -1 if EOF or error, -2 if the
   input buffer is full. */
ssize_t i_stream_read(struct istream *stream);
/* Skip forward a number of bytes. Never fails, the next read tells if it
   was successful. */
void i_stream_skip(struct istream *stream, uoff_t count);
/* Seek to specified position from beginning of file. Never fails, the next
   read tells if it was successful. This works only for files. */
void i_stream_seek(struct istream *stream, uoff_t v_offset);
/* Gets the next line from stream and returns it, or NULL if more data is
   needed to make a full line. NOTE: modifies the data in buffer for the \0,
   so it works only with buffered streams (currently only file). */
char *i_stream_next_line(struct istream *stream);
/* Like i_stream_next_line(), but reads for more data if needed. Returns NULL
   if more data is needed or error occured. */
char *i_stream_read_next_line(struct istream *stream);
/* Returns pointer to beginning of read data, or NULL if there's no data
   buffered. */
const unsigned char *i_stream_get_data(struct istream *stream, size_t *size);
/* Like i_stream_get_data(), but returns non-const data. This only works with
   buffered streams (currently only file), others return NULL. */
unsigned char *i_stream_get_modifyable_data(struct istream *stream,
					    size_t *size);
/* Like i_stream_get_data(), but read more when needed. Returns 1 if more
   than threshold bytes are available, 0 if less, -1 if error or EOF with no
   bytes available, or -2 if stream's input buffer is full. */
int i_stream_read_data(struct istream *stream, const unsigned char **data,
		       size_t *size, size_t threshold);

#endif
