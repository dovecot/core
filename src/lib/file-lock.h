#ifndef __FILE_LOCK_H
#define __FILE_LOCK_H

#include <unistd.h>
#include <fcntl.h>

/* Lock whole file descriptor. Returns 1 if successful, 0 if lock failed,
   or -1 if error. lock_type is F_WRLCK, F_RDLCK or F_UNLCK. */
int file_try_lock(int fd, int lock_type);

/* Lock whole file descriptor. Returns 1 if successful, or -1 if error. */
int file_wait_lock(int fd, int lock_type);

#endif
