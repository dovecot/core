#ifndef __OBUFFER_H
#define __OBUFFER_H

struct _OBuffer {
	uoff_t offset;

	int buf_errno;
	unsigned int closed:1;

	void *real_buffer;
};

OBuffer *o_buffer_create_file(int fd, Pool pool, size_t max_buffer_size,
			      int priority, int autoclose_fd);

/* Reference counting. References start from 1, so calling o_buffer_unref()
   destroys the buffer if o_buffer_ref() is never used. */
void o_buffer_ref(OBuffer *buf);
void o_buffer_unref(OBuffer *buf);

/* Mark the buffer closed. Nothing will be sent after this call. */
void o_buffer_close(OBuffer *buf);

/* Change the maximum size for buffer to grow. */
void o_buffer_set_max_size(OBuffer *buf, size_t max_size);
/* Buffer is made to be flushed out whenever it gets full (assumes max_size
   is already set), ie. writes will never be partial. Also makes any blocking
   writes to fail after specified timeout, calling timeout_func if it's
   set. This call changes non-blocking state of file descriptor. */
void o_buffer_set_blocking(OBuffer *buf, int timeout_msecs,
			   void (*timeout_func)(void *), void *context);

/* Delays sending as far as possible, writing only full buffers. Also sets
   TCP_CORK on if supported. o_buffer_flush() removes the cork. */
void o_buffer_cork(OBuffer *buf);
/* Flush the output buffer, blocks until everything is sent.
   Returns 1 if ok, -1 if error. */
int o_buffer_flush(OBuffer *buf);
/* Returns 1 if specified amount of data fits into buffer before reaching
   max_size, 0 if not. */
int o_buffer_have_space(OBuffer *buf, size_t size);

/* Seek to specified position from beginning of file. This works only for
   files. Returns 1 if successful, -1 if error. */
int o_buffer_seek(OBuffer *buf, uoff_t offset);
/* Returns number of bytes sent or buffered, or -1 if disconnected */
ssize_t o_buffer_send(OBuffer *buf, const void *data, size_t size);
/* Send data from input buffer to output buffer using the fastest
   possible method. Returns number of bytes sent, or -1 if error.
   Note that this function may block if either inbuf or outbuf is blocking. */
off_t o_buffer_send_ibuffer(OBuffer *outbuf, IBuffer *inbuf);

#endif
