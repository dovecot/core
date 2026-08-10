#ifndef WRITE_FULL_H
#define WRITE_FULL_H

/* Write data into file. Returns -1 if error occurred, or 0 if all was ok.
   If there's not enough space in device, -1 with ENOSPC is returned, and
   it's unspecified how much data was actually written. */
int write_full(int fd, const void *data, size_t size);
/* Same as write_full(), but also return the number of bytes that were
   successfully written. */
int write_full_count(int fd, const void *data, size_t size,
		     size_t *written_r);
int pwrite_full(int fd, const void *data, size_t size, off_t offset);

#endif
