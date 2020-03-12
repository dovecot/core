#ifndef SENDFILE_UTIL_H
#define SENDFILE_UTIL_H

/* Wrapper for various sendfile()-like calls. Read a maximum of count bytes
   from the given offset in in_fd and write them to out_fd. The offset is
   updated after the call. Note the call assert-crashes if count is 0.

   Returns:
   >0 number of bytes successfully written (maybe less than count)
   0 if offset points to the input's EOF or past it
   -1, errno=EINVAL if it isn't supported for some reason (out_fd isn't a
       socket or there simply is no sendfile()).
   -1, errno=EAGAIN if non-blocking write couldn't send anything */
ssize_t safe_sendfile(int out_fd, int in_fd, uoff_t *offset, size_t count);

#endif
