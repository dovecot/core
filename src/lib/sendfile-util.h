#ifndef __SENDFILE_UTIL_H
#define __SENDFILE_UTIL_H

/* simple wrapper for sendfile(), allowing usage of 64bit off_t with it */
ssize_t safe_sendfile(int out_fd, int in_fd, uoff_t *offset, size_t count);

#endif
