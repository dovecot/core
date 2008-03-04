#ifndef FDATASYNC_PATH_H
#define FDATASYNC_PATH_H

/* Open and fdatasync() the path. Works for files and directories. */
int fdatasync_path(const char *path);

#endif
