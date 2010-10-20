#ifndef FILE_SET_SIZE_H
#define FILE_SET_SIZE_H

/* Shrink/grow file. If file is grown, the new data is guaranteed to
   be zeros. The file offset may be anywhere after this call.
   Returns -1 if failed, 0 if successful. */
int file_set_size(int fd, off_t size);
/* Preallocate file to given size, without actually changing the size
   reported by stat(). Returns 1 if ok, 0 if not supported by this filesystem,
   -1 if error. */
int file_preallocate(int fd, off_t size);

#endif
