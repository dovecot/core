#ifndef FD_CLOSE_ON_EXEC_H
#define FD_CLOSE_ON_EXEC_H

/* Change close-on-exec flag of fd. */
void fd_close_on_exec(int fd, bool set);

/* Verify that fds in given range don't exist. */
void fd_debug_verify_leaks(int first_fd, int last_fd);

#endif
