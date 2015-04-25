#ifndef ISTREAM_UNIX_H
#define ISTREAM_UNIX_H

struct istream *i_stream_create_unix(int fd, size_t max_buffer_size);
/* Start trying to read a file descriptor from the UNIX socket. */
void i_stream_unix_set_read_fd(struct istream *input);
/* Stop trying to read a file descriptor from the UNIX socket. */
void i_stream_unix_unset_read_fd(struct istream *input);
/* Returns the fd that the last i_stream_read() received, or -1 if no fd
   was received. This function must be called before
   i_stream_unix_set_read_fd() is called again after successfully receiving
   a file descriptor. */
int i_stream_unix_get_read_fd(struct istream *input);

#endif
