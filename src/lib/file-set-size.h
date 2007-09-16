#ifndef FILE_SET_SIZE_H
#define FILE_SET_SIZE_H

/* Shrink/grow file. If file is grown, the new data is guaranteed to
   be zeros. The file offset may be anywhere after this call.
   Returns -1 if failed, 0 if successful. */
int file_set_size(int fd, off_t size);

#endif
