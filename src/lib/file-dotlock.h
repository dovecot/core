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

   callback is called once in a while. stale is set to TRUE if stale lock is
   detected and will be overridden in secs_left. If callback returns FALSE
   then, the lock will not be overridden. */
int file_lock_dotlock(const char *path, int checkonly,
		      unsigned int timeout, unsigned int stale_timeout,
		      int (*callback)(unsigned int secs_left, int stale,
				      void *context),
		      void *context, struct dotlock *dotlock_r);

/* Delete the dotlock file. Returns 1 if successful, 0 if the file was already
   been deleted or reused by someone else, -1 if error. */
int file_unlock_dotlock(const char *path, const struct dotlock *dotlock);

#endif
