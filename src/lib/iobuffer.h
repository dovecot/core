#ifndef __IOBUFFER_H
#define __IOBUFFER_H

#include "ioloop.h"

#define IO_BUFFER_MIN_SIZE		512

typedef void (*IOBufferFlushFunc) (void *context, IOBuffer *buf);

struct _IOBuffer {
	int fd;

	uoff_t start_offset;
	uoff_t offset, size; /* virtual offset, 0 = start_offset */

/* private: */
	Pool pool;
	IO io;
	int priority;

	int timeout_msecs;
	TimeoutFunc timeout_func;
	void *timeout_context;

	IOBufferFlushFunc flush_func;
	void *flush_context;

	unsigned char *buffer;
        unsigned int cr_lookup_pos; /* used only when reading a line */

	off_t mmap_offset;
	unsigned int pos, skip;
	unsigned int buffer_size, max_buffer_size;

	unsigned int file:1; /* reading/writing a file */
	unsigned int mmaped:1; /* reading a file with mmap() */
	unsigned int closed:1; /* all further read/writes will return 0 */
	unsigned int transmit:1; /* this is a transmit buffer */
	unsigned int receive:1; /* this is a receive buffer */
	unsigned int last_cr:1; /* we're expecting a LF to be skipped in
		next call to io_buffer_next_line() */
	unsigned int blocking:1; /* writes block if buffer is full */
	unsigned int corked:1; /* TCP_CORK set */
};

/* Create an I/O buffer. It can be used for either sending or receiving data,
   NEVER BOTH AT SAME TIME. */
IOBuffer *io_buffer_create(int fd, Pool pool, int priority,
			   unsigned int max_buffer_size);
/* Same as io_buffer_create(), but specify that we're reading/writing file. */
IOBuffer *io_buffer_create_file(int fd, Pool pool,
				unsigned int max_buffer_size);
/* Read the file by mmap()ing it in blocks. stop_offset specifies where to
   stop reading, or 0 to end of file. */
IOBuffer *io_buffer_create_mmap(int fd, Pool pool, unsigned int block_size,
				uoff_t size);
/* Destroy a buffer. */
void io_buffer_destroy(IOBuffer *buf);
/* Mark the buffer closed. Any sends/reads after this will return -1.
   The data already in buffer can be used, and the remaining output buffer
   will be sent. */
void io_buffer_close(IOBuffer *buf);
/* Reset all pointers so that the buffer looks empty, the actual data is
   not touched and can be used. */
void io_buffer_reset(IOBuffer *buf);

/* Change the memory pool used by the buffer. Data already in
   buffer will be transferred to new buffer. */
IOBuffer *io_buffer_set_pool(IOBuffer *buf, Pool pool);
/* Change the maximum size for buffer to grow. */
void io_buffer_set_max_size(IOBuffer *buf, unsigned int max_size);
/* Change output buffer's blocking state. When buffer reaches max_size,
   it will block until all the data has been sent or timeout has been
   reached. Setting max_size to 0 disables this (default). Setting
   timeout_msecs to 0 may block infinitely. */
void io_buffer_set_send_blocking(IOBuffer *buf, unsigned int max_size,
				 int timeout_msecs, TimeoutFunc timeout_func,
				 void *context);

/* Set TCP_CORK on if supported, ie. don't send out partial frames.
   io_buffer_send_flush() removes the cork. */
void io_buffer_cork(IOBuffer *buf);

/* Returns 1 if all was ok, -1 if disconnected, -2 if buffer is full */
int io_buffer_send(IOBuffer *buf, const void *data, unsigned int size);
/* Send data from input buffer to output buffer using the fastest
   possible method. Returns 1 if all was ok, -1 if disconnected.
   Note that this function may block. */
int io_buffer_send_buf(IOBuffer *outbuf, IOBuffer *inbuf, unsigned int size);
/* Flush the output buffer, blocks until all is sent. If
   io_buffer_set_send_blocking() is called, it's timeout settings are used. */
void io_buffer_send_flush(IOBuffer *buf);
/* Call specified function when the whole transmit buffer has been sent.
   If the buffer is empty already, the function will be called immediately.
   The function will be called only once. */
void io_buffer_send_flush_callback(IOBuffer *buf, IOBufferFlushFunc func,
				   void *context);

/* Returns number of bytes read if read was ok,
   -1 if disconnected / EOF, -2 if the buffer is full */
int io_buffer_read(IOBuffer *buf);
/* Like io_buffer_read(), but don't read more than specified size. */
int io_buffer_read_max(IOBuffer *buf, unsigned int size);
/* Skip forward a number of bytes */
void io_buffer_skip(IOBuffer *buf, uoff_t size);
/* Seek to specified position from beginning of file. This works only for
   files. Returns TRUE if successful. */
int io_buffer_seek(IOBuffer *buf, uoff_t offset);
/* Returns the next line from input buffer, or NULL if more data is needed
   to make a full line. NOTE: call to io_buffer_read() invalidates the
   returned data. */
char *io_buffer_next_line(IOBuffer *buf);
/* Returns pointer to beginning of data in buffer,
   or NULL if there's no data. */
unsigned char *io_buffer_get_data(IOBuffer *buf, unsigned int *size);
/* Like io_buffer_get_data(), but read it when needed. There always must be
   more than `threshold' bytes in buffer. Returns 1 if data was read, 0 if
   read was interrupted or nonblocking, -1 if EOF / error */
int io_buffer_read_data(IOBuffer *buf, unsigned char **data,
			unsigned int *size, unsigned int threshold);

/* Returns a pointer to buffer wanted amount of space,
   or NULL if size is too big. */
unsigned char *io_buffer_get_space(IOBuffer *buf, unsigned int size);
/* Send data saved to buffer from io_buffer_get_space().
   Returns -1 if disconnected. */
int io_buffer_send_buffer(IOBuffer *buf, unsigned int size);

/* Put data to buffer as if it was received.
   Returns 1 if successful, -2 if buffer isn't big enough. */
int io_buffer_set_data(IOBuffer *buf, const void *data, unsigned int size);
/* Returns TRUE if there's nothing in buffer. */
int io_buffer_is_empty(IOBuffer *buf);

#endif
