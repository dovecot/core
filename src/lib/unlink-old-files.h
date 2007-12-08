#ifndef UNLINK_OLD_FILES_H
#define UNLINK_OLD_FILES_H

/* Unlink all files from directory beginning with given prefix and having
   ctime older than min_time. Returns -1 if there were some errors. */
int unlink_old_files(const char *dir, const char *prefix, time_t min_time);

#endif
