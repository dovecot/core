#ifndef __ISTREAM_H
#define __ISTREAM_H

struct _IStream {
	uoff_t start_offset;
	uoff_t v_offset, v_size, v_limit; /* relative to start_offset */

	int stream_errno;
	unsigned int closed:1;

	void *real_stream;
};

IStream *i_stream_create_file(int fd, Pool pool, size_t max_buffer_size,
			      int autoclose_fd);
IStream *i_stream_create_mmap(int fd, Pool pool, size_t block_size,
			      uoff_t start_offset, uoff_t v_size,
			      int autoclose_fd);
IStream *i_stream_create_from_data(Pool pool, const unsigned char *data,
				   size_t size);

/* Reference counting. References start from 1, so calling i_stream_unref()
   destroys the stream if i_stream_ref() is never used. */
void i_stream_ref(IStream *stream);
void i_stream_unref(IStream *stream);

/* Return file descriptor for stream, or -1 if none is available. */
int i_stream_get_fd(IStream *stream);

/* Mark the stream closed. Any reads after this will return -1. The data
   already read can still be used. */
void i_stream_close(IStream *stream);

/* Change the maximum size for stream's input buffer to grow. Useful only
   for buffered streams (currently only file). */
void i_stream_set_max_buffer_size(IStream *stream, size_t max_size);
/* Change the start_offset and drop all data in buffers. Doesn't do anything
   if offset is the same as existing start_offset. */
void i_stream_set_start_offset(IStream *stream, uoff_t offset);
/* Stream won't be read past specified offset. Giving 0 as offset
   removes the limit. */
void i_stream_set_read_limit(IStream *stream, uoff_t v_offset);
/* Makes reads blocking until at least one byte is read. timeout_func is
   called if nothing is read in specified time. Setting timeout_msecs to 0
   makes it non-blocking. This call changes non-blocking state of file
   descriptor. */
void i_stream_set_blocking(IStream *stream, int timeout_msecs,
			   void (*timeout_func)(void *), void *context);

/* Returns number of bytes read if read was ok, -1 if EOF or error, -2 if the
   input buffer is full. */
ssize_t i_stream_read(IStream *stream);
/* Skip forward a number of bytes. Never fails, the next read tells if it
   was successful. */
void i_stream_skip(IStream *stream, uoff_t count);
/* Seek to specified position from beginning of file. Never fails, the next
   read tells if it was successful. This works only for files. */
void i_stream_seek(IStream *stream, uoff_t v_offset);
/* Reads the next line from stream and returns it, or NULL if more data is
   needed to make a full line. NOTE: modifies the data in buffer for the \0,
   so it works only with buffered streams (currently only file). */
char *i_stream_next_line(IStream *stream);
/* Returns pointer to beginning of read data, or NULL if there's no data
   buffered. */
const unsigned char *i_stream_get_data(IStream *stream, size_t *size);
/* Like i_stream_get_data(), but returns non-const data. This only works with
   buffered streams (currently only file), others return NULL. */
unsigned char *i_stream_get_modifyable_data(IStream *stream, size_t *size);
/* Like i_stream_get_data(), but read more when needed. Returns 1 if more
   than threshold bytes are available, 0 if less, -1 if error or EOF with no
   bytes available, or -2 if stream's input buffer is full. */
int i_stream_read_data(IStream *stream, const unsigned char **data,
		       size_t *size, size_t threshold);

#endif
