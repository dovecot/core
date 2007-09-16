#ifndef SENDFILE_UTIL_H
#define SENDFILE_UTIL_H

/* Wrapper for various sendfile()-like calls. Returns -1 and errno=EINVAL if
   it isn't supported for some reason (out_fd isn't a socket, offset is too
   large, or there simply is no sendfile()). */
ssize_t safe_sendfile(int out_fd, int in_fd, uoff_t *offset, size_t count);

#endif
