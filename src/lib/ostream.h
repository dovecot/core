#ifndef __OSTREAM_H
#define __OSTREAM_H

struct ostream {
	uoff_t offset;

	int stream_errno;
	unsigned int closed:1;

	struct _ostream *real_stream;
};

/* Create new output stream from given file descriptor.
   If max_buffer_size is 0, an "optimal" buffer size is used (max 128kB). */
struct ostream *
o_stream_create_file(int fd, pool_t pool, size_t max_buffer_size,
		     int autoclose_fd);

/* Reference counting. References start from 1, so calling o_stream_unref()
   destroys the stream if o_stream_ref() is never used. */
void o_stream_ref(struct ostream *stream);
void o_stream_unref(struct ostream *stream);

/* Mark the stream closed. Nothing will be sent after this call. */
void o_stream_close(struct ostream *stream);

/* Change the maximum size for stream's output buffer to grow. */
void o_stream_set_max_buffer_size(struct ostream *stream, size_t max_size);
/* Stream is made to be flushed out whenever it gets full (assumes max_size
   is already set), ie. writes will never be partial. Also makes any blocking
   writes to fail after specified timeout, calling timeout_cb if it's
   set. This call changes non-blocking state of file descriptor. */
void o_stream_set_blocking(struct ostream *stream, int timeout_msecs,
			   void (*timeout_cb)(void *), void *context);

/* Delays sending as far as possible, writing only full buffers. Also sets
   TCP_CORK on if supported. o_stream_flush() removes the cork. */
void o_stream_cork(struct ostream *stream);
/* Flush the output stream, blocks until everything is sent.
   Returns 1 if ok, -1 if error. */
int o_stream_flush(struct ostream *stream);
/* Returns 1 if specified amount of data currently fits into stream's output
   buffer, 0 if not. */
int o_stream_have_space(struct ostream *stream, size_t size);

/* Seek to specified position from beginning of file. This works only for
   files. Returns 1 if successful, -1 if error. */
int o_stream_seek(struct ostream *stream, uoff_t offset);
/* Returns number of bytes sent or buffered, or -1 if disconnected */
ssize_t o_stream_send(struct ostream *stream, const void *data, size_t size);
ssize_t o_stream_send_str(struct ostream *stream, const char *str);
/* Send data from input stream. Returns number of bytes sent, or -1 if error.
   Note that this function may block if either instream or outstream is
   blocking.

   It's also possible to use this function to copy data within same file
   descriptor. If the file must be grown, you have to do it manually before
   calling this function. */
off_t o_stream_send_istream(struct ostream *outstream,
			    struct istream *instream);

#endif
