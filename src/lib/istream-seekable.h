#ifndef ISTREAM_SEEKABLE_H
#define ISTREAM_SEEKABLE_H

/* Create a seekable stream from given NULL-terminated list of input streams.
   Try to keep it in memory, but use a temporary file if it's too large.

   When max_buffer_size is reached, fd_callback is called. It should return
   the fd and path of the created file. Typically the callback would also
   unlink the file before returning. */
struct istream *
i_stream_create_seekable(struct istream *input[],
			 size_t max_buffer_size,
			 int (*fd_callback)(const char **path_r, void *context),
			 void *context);

#endif
