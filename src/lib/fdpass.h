#ifndef __FDPASS_H
#define __FDPASS_H

/* Returns number of bytes sent, -1 if error. */
int fd_send(int handle, int send_fd, const void *data, int size);

/* Returns number of bytes read, or -1 if error. fd is set only
   if return value is larger than 0. */
int fd_read(int handle, void *data, int size, int *fd);

#endif
