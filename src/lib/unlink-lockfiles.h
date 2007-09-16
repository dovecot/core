#ifndef UNLINK_LOCKFILES_H
#define UNLINK_LOCKFILES_H

/* Delete stale lock files. Filenames beginning with pidprefix<PID> are
   deleted immediately if PID doesn't exist. Filenames beginning with
   otherprefix are deleted if their mtime and ctime is older than
   other_min_time.

   Returns 1 if everything was successful, 0 if some of the files
   couldn't be deleted, -1 if directory couldn't be opened at all. */
int unlink_lockfiles(const char *dir, const char *pidprefix,
		     const char *otherprefix, time_t other_min_time);

#endif
