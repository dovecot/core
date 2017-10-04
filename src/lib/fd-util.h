#ifndef FD_UTIL_H
#define FD_UTIL_H

/* Change close-on-exec flag of fd. */
void fd_close_on_exec(int fd, bool set);

/* Verify that fds in given range don't exist. */
void fd_debug_verify_leaks(int first_fd, int last_fd);

/* Set file descriptor to blocking/nonblocking state */
void fd_set_nonblock(int fd, bool nonblock);

/* Close fd_in and fd_out, unless they're already -1. They can point to the
   same fd, in which case they're closed only once. If they point to stdin
   or stdout, they're replaced with /dev/null. */
void fd_close_maybe_stdio(int *fd_in, int *fd_out);

#endif
