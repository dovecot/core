#ifndef __UNLINK_LOCKFILES_H
#define __UNLINK_LOCKFILES_H

/* Delete stale lock files. Filenames beginning with pidprefix<PID> are
   deleted immediately if PID doesn't exist. Filenames beginning with
   otherprefix are deleted if their mtime and ctime is older than
   other_min_time. */
int unlink_lockfiles(const char *dir, const char *pidprefix,
		     const char *otherprefix, time_t other_min_time);

#endif
