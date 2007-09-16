#ifndef ISTREAM_SEEKABLE_H
#define ISTREAM_SEEKABLE_H

/* Create a seekable stream from given NULL-terminated list of input streams.
   Try to keep it in memory, but use a temporary file if it's too large.

   temp_prefix is used as path and filename prefix for creating the file.
   It will be appended by PID, timestamp and 128 bits of weak randomness. */
struct istream *
i_stream_create_seekable(struct istream *input[],
			 size_t max_buffer_size, const char *temp_prefix);

#endif
