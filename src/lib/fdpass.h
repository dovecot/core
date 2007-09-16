#ifndef FDPASS_H
#define FDPASS_H

/* Returns number of bytes sent, -1 if error. send_fd can be -1 if we just
   want to send the data with sendmsg(). */
ssize_t fd_send(int handle, int send_fd, const void *data, size_t size);

/* Returns number of bytes read, or -1 if error. fd is set -1 if read was only
   partial (returns 0) or data was received without a passed fd. */
ssize_t fd_read(int handle, void *data, size_t size, int *fd);

#endif
