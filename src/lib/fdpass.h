#ifndef FDPASS_H
#define FDPASS_H

/* Send data and send_fd (unless it's -1) via sendmsg(). Returns number of
   bytes sent, or -1 on error. If at least 1 byte was sent, the send_fd was
   also sent. */
ssize_t fd_send(int handle, int send_fd, const void *data, size_t size);

/* Receive data and fd via recvmsg(). Returns number of bytes read, 0 on
   disconnection, or -1 on error. If at least 1 byte was read, the fd is also
   returned (if it had been sent). If there was no fd received, it's set to
   -1. See test-istream-unix.c for different test cases. */
ssize_t fd_read(int handle, void *data, size_t size, int *fd_r);

#endif
