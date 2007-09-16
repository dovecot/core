#ifndef READ_FULL_H
#define READ_FULL_H

/* Read data from file. Returns -1 if error occurred, or 0 if EOF came before
   everything was read, or 1 if all was ok. */
int read_full(int fd, void *data, size_t size);
int pread_full(int fd, void *data, size_t size, off_t offset);

#endif
