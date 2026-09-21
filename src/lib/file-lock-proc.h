#ifndef FILE_LOCK_PROC_H
#define FILE_LOCK_PROC_H

#include "file-lock.h"

struct istream;

enum proc_lock_class {
	/* Lock type wasn't recognized (e.g. a lease or a delegation). */
	PROC_LOCK_CLASS_UNKNOWN = 0,
	/* fcntl() POSIX record lock, owned by a process. */
	PROC_LOCK_CLASS_POSIX,
	/* flock() lock, owned by an open file description. */
	PROC_LOCK_CLASS_FLOCK,
	/* fcntl() open file description lock. */
	PROC_LOCK_CLASS_OFD,

	PROC_LOCK_CLASS_COUNT
};

struct proc_lock {
	/* Lock ID. A lock that is still waiting to be granted has the same ID
	   as the lock that is blocking it. */
	unsigned int id;
	enum proc_lock_class lock_class;

	/* Device and inode of the locked file. */
	unsigned int dev_major, dev_minor;
	ino_t ino;
	/* Locked byte range. end is inclusive, UOFF_T_MAX means EOF. */
	uoff_t start, end;

	/* PID of the lock owner. 0 if it's unknown, e.g. because the owner is
	   in another PID namespace. -1 for open file description locks, which
	   aren't owned by any specific process. */
	pid_t pid;

	/* TRUE for a write lock, FALSE for a read lock. */
	bool write:1;
	/* TRUE if the lock isn't granted yet, but is waiting for the lock
	   with the same id to be released. */
	bool waiter:1;
};
ARRAY_DEFINE_TYPE(proc_lock, struct proc_lock);

/* Parse a single /proc/locks line. Returns 0 on success, or -1 if the line
   isn't a lock this API knows how to describe. */
int file_lock_proc_parse_line(const char *line, struct proc_lock *lock_r);
/* Parse /proc/locks content from input, appending each successfully parsed
   line to locks. Returns 0 on success, or -1 if reading input failed. */
int file_lock_proc_parse(struct istream *input, ARRAY_TYPE(proc_lock) *locks);

/* Returns human-readable string containing the process that has the file
   currently locked, based on the Linux /proc/locks file. Returns "" if
   unknown or if /proc/locks can't be used, otherwise " (string)". Only
   locks that could have blocked a lock_method lock are reported. */
const char *file_lock_proc_find(int lock_fd,
				enum file_lock_method lock_method);

#endif
