#ifndef __FILE_LOCK_H
#define __FILE_LOCK_H

#include <unistd.h>
#include <fcntl.h>

#define DEFAULT_LOCK_TIMEOUT 120

/* Lock whole file descriptor. Returns 1 if successful, 0 if lock failed,
   or -1 if error. lock_type is F_WRLCK, F_RDLCK or F_UNLCK. */
int file_try_lock(int fd, int lock_type);

/* Lock whole file descriptor. Returns 1 if successful, 0 if timeout or
   -1 if error. When returning 0, errno is also set to EAGAIN.
   NOTE: timeout uses SIGALRM and resets it at the end. */
int file_wait_lock(int fd, int lock_type, unsigned int timeout);

#endif
