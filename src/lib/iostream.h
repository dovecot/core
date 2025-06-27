#ifndef IOSTREAM_H
#define IOSTREAM_H

struct iostream_fd {
	int refcount;
	int fd;
};

/* Used to allow autoclosing fds with istream-file and ostream-file without
   requiring them to be closed in any specific order. */
struct iostream_fd *iostream_fd_init(int fd);
void iostream_fd_ref(struct iostream_fd *ref);
bool iostream_fd_unref(struct iostream_fd **ref);

/* Create i/ostreams for the given fd. The fd is set to -1 immediately to avoid
   accidentally closing it twice. */
void io_stream_create_fd_autoclose(int *fd, size_t max_in_buffer_size,
				   size_t max_out_buffer_size,
				   struct istream **input_r,
				   struct ostream **output_r);

/* Returns human-readable reason for why iostream was disconnected.
   The output is either "Connection closed" for clean disconnections or
   "Connection closed: <error>" for unclean disconnections. */
const char *io_stream_get_disconnect_reason(struct istream *input,
					    struct ostream *output);

#endif
