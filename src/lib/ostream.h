#ifndef OSTREAM_H
#define OSTREAM_H

#include "ioloop.h"

enum ostream_send_istream_result {
	/* All of the istream was successfully sent to ostream. */
	OSTREAM_SEND_ISTREAM_RESULT_FINISHED,
	/* Caller needs to wait for more input from non-blocking istream. */
	OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT,
	/* Caller needs to wait for output to non-blocking ostream.
	   o_stream_set_flush_pending() is automatically called. */
	OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT,
	/* Read from istream failed. See istream->stream_errno. */
	OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT,
	/* Write to ostream failed. See ostream->stream_errno. */
	OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT
};

enum ostream_create_file_flags {
	/* without append, file is truncated */
	OSTREAM_CREATE_FILE_FLAG_APPEND = BIT(0),
};

struct ostream {
	/* Number of bytes sent via o_stream_send*() and similar functions.
	   This is counting the input data. For example with a compressed
	   ostream this is counting the uncompressed bytes. The compressed
	   bytes could be counted from the parent ostream's offset.

	   Seeking to a specified offset only makes sense if there is no
	   difference between input and output data sizes (e.g. there are no
	   wrapper ostreams changing the data). */
	uoff_t offset;

	/* errno for the last operation send/seek operation. cleared before
	   each call. */
	int stream_errno;

	/* overflow is set when some of the data given to send()
	   functions was neither sent nor buffered. It's never unset inside
	   ostream code. */
	bool overflow:1;
	/* o_stream_send() writes all the data or returns failure */
	bool blocking:1;
	bool closed:1;

	struct ostream_private *real_stream;
};

/* Returns 1 if all data is sent (not necessarily flushed), 0 if not.
   Pretty much the only real reason to return 0 is if you wish to send more
   data to client which isn't buffered, eg. o_stream_send_istream(). */
typedef int stream_flush_callback_t(void *context);
typedef void ostream_callback_t(void *context);

/* Create new output stream from given file descriptor.
   If max_buffer_size is 0, an "optimal" buffer size is used (max 128kB). */
struct ostream *o_stream_create_fd(int fd, size_t max_buffer_size);
/* The fd is set to -1 immediately to avoid accidentally closing it twice. */
struct ostream *o_stream_create_fd_autoclose(int *fd, size_t max_buffer_size);
/* Create an output stream from a regular file which begins at given offset.
   If offset==(uoff_t)-1, the current offset isn't known. */
struct ostream *
o_stream_create_fd_file(int fd, uoff_t offset, bool autoclose_fd);
struct ostream *o_stream_create_fd_file_autoclose(int *fd, uoff_t offset);
/* Create ostream for file. If append flag is not set, file will be truncated. */
struct ostream *o_stream_create_file(const char *path, uoff_t offset, mode_t mode,
				     enum ostream_create_file_flags flags);
/* Create an output stream to a buffer. */
struct ostream *o_stream_create_buffer(buffer_t *buf);
/* Create an output streams that always fails the writes. */
struct ostream *o_stream_create_error(int stream_errno);
struct ostream *
o_stream_create_error_str(int stream_errno, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
/* Create an output stream that simply passes through data. This is mainly
   useful as a wrapper when combined with destroy callbacks. */
struct ostream *o_stream_create_passthrough(struct ostream *output);

/* Set name (e.g. path) for output stream. */
void o_stream_set_name(struct ostream *stream, const char *name);
/* Get output stream's name. Returns "" if stream has no name. */
const char *o_stream_get_name(struct ostream *stream);

/* Return file descriptor for stream, or -1 if none is available. */
int o_stream_get_fd(struct ostream *stream);
/* Returns error string for the previous error. */
const char *o_stream_get_error(struct ostream *stream);

/* Close this stream (but not its parents) and unreference it. */
void o_stream_destroy(struct ostream **stream);
/* Reference counting. References start from 1, so calling o_stream_unref()
   destroys the stream if o_stream_ref() is never used. */
void o_stream_ref(struct ostream *stream);
/* Unreferences the stream and sets stream pointer to NULL. */
void o_stream_unref(struct ostream **stream);
/* Call the given callback function when stream is destroyed. */
void o_stream_add_destroy_callback(struct ostream *stream,
				   ostream_callback_t *callback, void *context)
	ATTR_NULL(3);
#define o_stream_add_destroy_callback(stream, callback, context) \
	o_stream_add_destroy_callback(stream - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(ostream_callback_t *)callback, context)
/* Remove the destroy callback. */
void o_stream_remove_destroy_callback(struct ostream *stream,
				      void (*callback)());

/* Mark the stream and all of its parent streams closed. Nothing will be
   sent after this call. When using ostreams that require writing a trailer,
   o_stream_finish() must be used before the stream is closed. When ostream
   is destroyed, it's also closed but its parents aren't.

   Closing the ostream (also via destroy) will first flush the ostream, and
   afterwards requires one of: a) stream has failed, b) there is no more
   buffered data, c) o_stream_set_no_error_handling() has been called. */
void o_stream_close(struct ostream *stream);

/* Set IO_WRITE callback. Default will just try to flush the output and
   finishes when the buffer is empty.  */
void o_stream_set_flush_callback(struct ostream *stream,
				 stream_flush_callback_t *callback,
				 void *context) ATTR_NULL(3);
#define o_stream_set_flush_callback(stream, callback, context) \
	o_stream_set_flush_callback(stream - \
		CALLBACK_TYPECHECK(callback, int (*)(typeof(context))), \
		(stream_flush_callback_t *)callback, context)
void o_stream_unset_flush_callback(struct ostream *stream);
/* Change the maximum size for stream's output buffer to grow. */
void o_stream_set_max_buffer_size(struct ostream *stream, size_t max_size);
/* Returns the current max. buffer size. */
size_t o_stream_get_max_buffer_size(struct ostream *stream);

/* Delays sending as far as possible, writing only full buffers. Also sets
   TCP_CORK on if supported. */
void o_stream_cork(struct ostream *stream);
/* Try to flush the buffer by calling o_stream_flush() and remove TCP_CORK.
   Note that after this o_stream_flush() must be called, unless the stream
   ignores errors. */
void o_stream_uncork(struct ostream *stream);
bool o_stream_is_corked(struct ostream *stream);
/* Try to flush the output stream. If o_stream_nsend*() had been used and
   the stream had overflown, return error. Returns 1 if all data is sent,
   0 there's still buffered data, -1 if error. */
int o_stream_flush(struct ostream *stream);
/* Wrapper to easily both uncork and flush. */
static inline int o_stream_uncork_flush(struct ostream *stream)
{
	o_stream_uncork(stream);
	return o_stream_flush(stream);
}

/* Set "flush pending" state of stream. If set, the flush callback is called
   when more data is allowed to be sent, even if the buffer itself is empty.
   Note that if the stream is corked, the flush callback won't be called until
   the stream is first uncorked. */
void o_stream_set_flush_pending(struct ostream *stream, bool set);
/* Returns the number of bytes currently in all the pending write buffers of
   this ostream, including its parent streams. This function is commonly used
   by callers to determine when they've filled up the ostream so they can stop
   writing to it. Because of this, the return value shouldn't include buffers
   that are expected to be filled up before they send anything to their parent
   stream. Otherwise the callers may stop writing to the stream too early and
   hang. Such an example could be a compression ostream that won't send
   anything to its parent stream before an internal compression buffer is
   full. */
size_t o_stream_get_buffer_used_size(const struct ostream *stream) ATTR_PURE;
/* Returns the (minimum) number of bytes we can still write without failing.
   This is commonly used by callers to find out how many bytes they're
   guaranteed to be able to send, and then generate that much data and send
   it. */
size_t o_stream_get_buffer_avail_size(const struct ostream *stream) ATTR_PURE;

/* Seek to specified position from beginning of file. This works only for
   files. Returns 1 if successful, -1 if error. */
int o_stream_seek(struct ostream *stream, uoff_t offset);
/* Returns number of bytes sent, -1 = error */
ssize_t o_stream_send(struct ostream *stream, const void *data, size_t size)
	ATTR_WARN_UNUSED_RESULT;
ssize_t o_stream_sendv(struct ostream *stream, const struct const_iovec *iov,
		       unsigned int iov_count) ATTR_WARN_UNUSED_RESULT;
ssize_t o_stream_send_str(struct ostream *stream, const char *str)
	ATTR_WARN_UNUSED_RESULT;
/* Send with delayed error handling. o_stream_flush() or
   o_stream_ignore_last_errors() must be called after these functions before
   the stream is destroyed. If any of the data can't be sent due to stream's
   buffer getting full, all further nsends are ignores and o_stream_flush()
   will fail. */
void o_stream_nsend(struct ostream *stream, const void *data, size_t size);
void o_stream_nsendv(struct ostream *stream, const struct const_iovec *iov,
		     unsigned int iov_count);
void o_stream_nsend_str(struct ostream *stream, const char *str);
/* Mark the ostream as finished and flush it. If the ostream has a footer,
   it's written here. Any further write attempts to the ostream will
   assert-crash. Returns the same as o_stream_flush(). Afterwards any calls to
   this function are identical to o_stream_flush(). */
int o_stream_finish(struct ostream *stream);
/* Specify whether calling o_stream_finish() will cause the parent stream to
   be finished as well. The default is yes. */
void o_stream_set_finish_also_parent(struct ostream *stream, bool set);
/* Specify whether calling o_stream_finish() on a child stream will cause
   this stream to be finished as well. The default is yes. */
void o_stream_set_finish_via_child(struct ostream *stream, bool set);
/* Marks the stream's error handling as completed to avoid i_panic() on
   destroy. */
void o_stream_ignore_last_errors(struct ostream *stream);
/* Abort writing to the ostream, also marking any previous error handling as
   completed. If the stream hasn't already failed, sets the stream_errno=EPIPE.
   This is necessary when aborting write to streams that require finishing. */
void o_stream_abort(struct ostream *stream);
/* If error handling is disabled, the i_panic() on destroy is never called.
   This function can be called immediately after the stream is created.
   When creating wrapper streams, they copy this behavior from the parent
   stream. */
void o_stream_set_no_error_handling(struct ostream *stream, bool set);
/* Send all of the instream to outstream.

   On non-failure instream is skips over all data written to outstream.
   This means that the number of bytes written to outstream is always equal to
   the number of bytes skipped in instream.

   It's also possible to use this function to copy data within same file
   descriptor, even if the source and destination overlaps. If the file must
   be grown, you have to do it manually before calling this function. */
enum ostream_send_istream_result ATTR_WARN_UNUSED_RESULT
o_stream_send_istream(struct ostream *outstream, struct istream *instream);
/* Same as o_stream_send_istream(), but assume that reads and writes will
   succeed. If not, o_stream_flush() will fail with the correct error
   message (even istream's). */
void o_stream_nsend_istream(struct ostream *outstream, struct istream *instream);

/* Write data to specified offset. Returns 0 if successful, -1 if error. */
int o_stream_pwrite(struct ostream *stream, const void *data, size_t size,
		    uoff_t offset);

/* Return the last timestamp when something was successfully sent to the
   ostream's internal buffers (no guarantees that anything was sent further).
   The timestamp is 0 if nothing has ever been written. */
void o_stream_get_last_write_time(struct ostream *stream, struct timeval *tv_r);

/* If there are any I/O loop items associated with the stream, move all of
   them to provided/current ioloop. */
void o_stream_switch_ioloop_to(struct ostream *stream, struct ioloop *ioloop);
void o_stream_switch_ioloop(struct ostream *stream);

#endif
