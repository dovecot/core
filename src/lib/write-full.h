#ifndef __WRITE_FULL_H
#define __WRITE_FULL_H

/* Write data into file. Returns -1 if error occured, or 0 if all was ok.
   If there's not enough space in device -1 with ENOSPC is returned, and
   it's unspecified how much data was actually written. */
int write_full(int fd, const void *data, size_t size);

#endif
