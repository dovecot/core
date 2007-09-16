#ifndef CLOSE_KEEP_ERRNO_H
#define CLOSE_KEEP_ERRNO_H

/* Close the file handle without changing errno. */
void close_keep_errno(int fd);

#endif
