#ifndef __OSTREAM_H
#define __OSTREAM_H

struct _OStream {
	uoff_t offset;

	int stream_errno;
	unsigned int closed:1;

	void *real_stream;
};

OStream *o_stream_create_file(int fd, Pool pool, size_t max_buffer_size,
			      int priority, int autoclose_fd);

/* Reference counting. References start from 1, so calling o_stream_unref()
   destroys the stream if o_stream_ref() is never used. */
void o_stream_ref(OStream *stream);
void o_stream_unref(OStream *stream);

/* Mark the stream closed. Nothing will be sent after this call. */
void o_stream_close(OStream *stream);

/* Change the maximum size for stream's output buffer to grow. */
void o_stream_set_max_buffer_size(OStream *stream, size_t max_size);
/* Stream is made to be flushed out whenever it gets full (assumes max_size
   is already set), ie. writes will never be partial. Also makes any blocking
   writes to fail after specified timeout, calling timeout_func if it's
   set. This call changes non-blocking state of file descriptor. */
void o_stream_set_blocking(OStream *stream, int timeout_msecs,
			   void (*timeout_func)(void *), void *context);

/* Delays sending as far as possible, writing only full buffers. Also sets
   TCP_CORK on if supported. o_stream_flush() removes the cork. */
void o_stream_cork(OStream *stream);
/* Flush the output stream, blocks until everything is sent.
   Returns 1 if ok, -1 if error. */
int o_stream_flush(OStream *stream);
/* Returns 1 if specified amount of data currently fits into stream's output
   buffer, 0 if not. */
int o_stream_have_space(OStream *stream, size_t size);

/* Seek to specified position from beginning of file. This works only for
   files. Returns 1 if successful, -1 if error. */
int o_stream_seek(OStream *stream, uoff_t offset);
/* Returns number of bytes sent or buffered, or -1 if disconnected */
ssize_t o_stream_send(OStream *stream, const void *data, size_t size);
ssize_t o_stream_send_str(OStream *stream, const char *str);
/* Send data from input stream. Returns number of bytes sent, or -1 if error.
   Note that this function may block if either instream or outstream is
   blocking. */
off_t o_stream_send_istream(OStream *outstream, IStream *instream);

#endif
