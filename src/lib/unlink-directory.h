#ifndef UNLINK_DIRECTORY_H
#define UNLINK_DIRECTORY_H

/* Unlink directory and/or everything under it.
   Returns 0 if successful, -1 if error. */
int unlink_directory(const char *dir, bool unlink_dir);

#endif
