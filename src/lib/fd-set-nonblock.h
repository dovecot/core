#ifndef FD_SET_NONBLOCK_H
#define FD_SET_NONBLOCK_H

/* Set file descriptor to blocking/nonblocking state */
int fd_set_nonblock(int fd, bool nonblock);

#endif
