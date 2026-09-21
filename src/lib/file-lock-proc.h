#ifndef FILE_LOCK_PROC_H
#define FILE_LOCK_PROC_H

/* Returns human-readable string containing the process that has the file
   currently locked, based on the Linux /proc/locks file. Returns "" if
   unknown or if /proc/locks can't be used, otherwise " (string)". */
const char *file_lock_proc_find(int lock_fd);

#endif
