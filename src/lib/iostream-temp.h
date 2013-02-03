#ifndef IOSTREAM_TEMP_H
#define IOSTREAM_TEMP_H

enum iostream_temp_flags {
	/* if o_stream_send_istream() is called with a readable fd, don't
	   actually copy the input stream, just have iostream_temp_finish()
	   return a new iostream pointing to the fd dup()ed */
	IOSTREAM_TEMP_FLAG_TRY_FD_DUP	= 0x01
};

/* Start writing to given output stream. The data is initially written to
   memory, and later to a temporary file that is immediately unlinked. */
struct ostream *iostream_temp_create(const char *temp_path_prefix,
				     enum iostream_temp_flags flags);
/* Finished writing to stream. Return input stream for it and free the
   output stream. */
struct istream *iostream_temp_finish(struct ostream **output,
				     size_t max_buffer_size);

#endif
