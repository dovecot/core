#ifndef OSTREAM_H
#define OSTREAM_H

#include "ioloop.h"

struct ostream {
	uoff_t offset;

	/* errno for the last operation send/seek operation. cleared before
	   each call. */
	int stream_errno;
	/* errno of the last failed send/seek. never cleared. */
	int last_failed_errno;

	/* overflow is set when some of the data given to send()
	   functions was neither sent nor buffered. It's never unset inside
	   ostream code. */
	unsigned int overflow:1;
	unsigned int closed:1;

	struct ostream_private *real_stream;
};

/* Returns 1 if all data is sent (not necessarily flushed), 0 if not.
   Pretty much the only real reason to return 0 is if you wish to send more
   data to client which isn't buffered, eg. o_stream_send_istream(). */
typedef int stream_flush_callback_t(void *context);

/* Create new output stream from given file descriptor.
   If max_buffer_size is 0, an "optimal" buffer size is used (max 128kB). */
struct ostream *
o_stream_create_fd(int fd, size_t max_buffer_size, bool autoclose_fd);
/* Create an output stream from a regular file which begins at given offset.
   If offset==(uoff_t)-1, the current offset isn't known. */
struct ostream *
o_stream_create_fd_file(int fd, uoff_t offset, bool autoclose_fd);
/* Create an output stream to a buffer. */
struct ostream *o_stream_create_buffer(buffer_t *buf);

/* Set name (e.g. path) for output stream. */
void o_stream_set_name(struct ostream *stream, const char *name);
/* Get output stream's name. Returns "" if stream has no name. */
const char *o_stream_get_name(struct ostream *stream);

/* o_stream_close() + o_stream_unref() */
void o_stream_destroy(struct ostream **stream);
/* Reference counting. References start from 1, so calling o_stream_unref()
   destroys the stream if o_stream_ref() is never used. */
void o_stream_ref(struct ostream *stream);
/* Unreferences the stream and sets stream pointer to NULL. */
void o_stream_unref(struct ostream **stream);

/* Mark the stream closed. Nothing will be sent after this call. */
void o_stream_close(struct ostream *stream);

/* Set IO_WRITE callback. Default will just try to flush the output and
   finishes when the buffer is empty.  */
void o_stream_set_flush_callback(struct ostream *stream,
				 stream_flush_callback_t *callback,
				 void *context);
#define o_stream_set_flush_callback(stream, callback, context) \
	CONTEXT_CALLBACK(o_stream_set_flush_callback, stream_flush_callback_t, \
			 callback, context, stream)
void o_stream_unset_flush_callback(struct ostream *stream);
/* Change the maximum size for stream's output buffer to grow. */
void o_stream_set_max_buffer_size(struct ostream *stream, size_t max_size);

/* Delays sending as far as possible, writing only full buffers. Also sets
   TCP_CORK on if supported. */
void o_stream_cork(struct ostream *stream);
void o_stream_uncork(struct ostream *stream);
/* Try to flush the output stream. Returns 1 if all sent, 0 if not,
   -1 if error. */
int o_stream_flush(struct ostream *stream);
/* Set "flush pending" state of stream. If set, the flush callback is called
   when more data is allowed to be sent, even if the buffer itself is empty. */
void o_stream_set_flush_pending(struct ostream *stream, bool set);
/* Returns number of bytes currently in buffer. */
size_t o_stream_get_buffer_used_size(const struct ostream *stream) ATTR_PURE;
/* Returns number of bytes we can still write without failing. */
size_t o_stream_get_buffer_avail_size(const struct ostream *stream) ATTR_PURE;

/* Seek to specified position from beginning of file. This works only for
   files. Returns 1 if successful, -1 if error. */
int o_stream_seek(struct ostream *stream, uoff_t offset);
/* Returns number of bytes sent, -1 = error */
ssize_t o_stream_send(struct ostream *stream, const void *data, size_t size);
ssize_t o_stream_sendv(struct ostream *stream, const struct const_iovec *iov,
		       unsigned int iov_count);
ssize_t o_stream_send_str(struct ostream *stream, const char *str);
/* Send data from input stream. Returns number of bytes sent, or -1 if error.
   Note that this function may block if either instream or outstream is
   blocking.

   Also note that this function may not add anything to the output buffer, so
   if you want the flush callback to be called when more data can be written,
   you'll need to call o_stream_set_flush_pending() manually.

   It's also possible to use this function to copy data within same file
   descriptor. If the file must be grown, you have to do it manually before
   calling this function. */
off_t o_stream_send_istream(struct ostream *outstream,
			    struct istream *instream);

/* Write data to specified offset. Returns 0 if successful, -1 if error. */
int o_stream_pwrite(struct ostream *stream, const void *data, size_t size,
		    uoff_t offset);

#endif
