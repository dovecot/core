#ifndef __FILE_DOTLOCK_H
#define __FILE_DOTLOCK_H

#include <unistd.h>
#include <fcntl.h>

struct dotlock {
	dev_t dev;
	ino_t ino;
	time_t mtime;
};

/* Create dotlock. Returns 1 if successful, 0 if timeout or -1 if error.
   When returning 0, errno is also set to EAGAIN.

   If file specified in path doesn't change in stale_timeout seconds and it's
   still locked, override the lock file.

   If checkonly is TRUE, we don't actually create the lock file, only make
   sure that it doesn't exist. This is racy, so you shouldn't rely on it.

   Dotlock files are created by first creating a temp file and then link()ing
   it to the dotlock. temp_prefix specifies the prefix to use for temp files.
   It may contain a full path. If it's NULL, ".temp.hostname.pid." is used

   callback is called once in a while. stale is set to TRUE if stale lock is
   detected and will be overridden in secs_left. If callback returns FALSE
   then, the lock will not be overridden. */
int file_lock_dotlock(const char *path, const char *temp_prefix, int checkonly,
		      unsigned int timeout, unsigned int stale_timeout,
		      unsigned int immediate_stale_timeout,
		      int (*callback)(unsigned int secs_left, int stale,
				      void *context),
		      void *context, struct dotlock *dotlock_r);

/* Delete the dotlock file. Returns 1 if successful, 0 if the file was already
   been deleted or reused by someone else, -1 if error. */
int file_unlock_dotlock(const char *path, const struct dotlock *dotlock);

/* Use dotlock as the new content for file. This provides read safety without
   locks, but not very good for large files. Returns fd for lock file.
   If locking timed out, returns -1 and errno = EAGAIN. */
int file_dotlock_open(const char *path,
		      const char *temp_prefix, const char *lock_suffix,
		      unsigned int timeout, unsigned int stale_timeout,
		      unsigned int immediate_stale_timeout,
		      int (*callback)(unsigned int secs_left, int stale,
				      void *context),
		      void *context);
/* Replaces path with path.lock file. Closes given fd. If verify_owner is TRUE,
   it checks that lock file hasn't been overwritten before renaming. */
int file_dotlock_replace(const char *path, const char *lock_suffix,
			 int fd, int verify_owner);
/* Like file_unlock_dotlock(). Closes given fd. */
int file_dotlock_delete(const char *path, const char *lock_suffix, int fd);

#endif
