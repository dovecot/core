#ifndef OSTREAM_UNIX_H
#define OSTREAM_UNIX_H

struct ostream *o_stream_create_unix(int fd, size_t max_buffer_size);
/* Write fd to UNIX socket along with the next outgoing data block.
   Returns TRUE if fd is accepted, and FALSE if a previous fd still
   needs to be sent. */
bool o_stream_unix_write_fd(struct ostream *output, int fd);

#endif
