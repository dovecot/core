#ifndef __FILE_SET_SIZE_H
#define __FILE_SET_SIZE_H

/* Shrink/grow file. If file is grown, the new data is guaranteed to
   be zeros. Returns -1 if failed, 0 if successful. */
int file_set_size(int fd, off_t size);

#endif
