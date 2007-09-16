#ifndef FILE_COPY_H
#define FILE_COPY_H

/* Copy file atomically. First try hardlinking, then fallback to creating
   a temporary file (destpath.tmp) and rename()ing it over srcpath.
   If the destination file already exists, it may or may not be overwritten,
   so that shouldn't be relied on.

   Returns -1 = error, 0 = source file not found, 1 = ok */
int file_copy(const char *srcpath, const char *destpath, bool try_hardlink);

#endif
