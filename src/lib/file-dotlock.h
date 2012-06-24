#ifndef FILE_DOTLOCK_H
#define FILE_DOTLOCK_H

#include <unistd.h>
#include <fcntl.h>

struct dotlock;

struct dotlock_settings {
	/* Dotlock files are created by first creating a temp file and then
	   link()ing it to the dotlock. temp_prefix specifies the prefix to
	   use for temp files. It may contain a full path. Default is
	   ".temp.hostname.pid.". */
	const char *temp_prefix;
	/* Use this suffix for dotlock filenames. Default is ".lock". */
	const char *lock_suffix;

	/* Abort after this many seconds. */
	unsigned int timeout;
	/* Override the lock file when it and the file we're protecting is
	   older than stale_timeout. */
	unsigned int stale_timeout;

	/* Callback is called once in a while. stale is set to TRUE if stale
	   lock is detected and will be overridden in secs_left. If callback
	   returns FALSE then, the lock will not be overridden. */
	bool (*callback)(unsigned int secs_left, bool stale, void *context);
	void *context;

	/* Rely on O_EXCL locking to work instead of using hardlinks.
	   It's faster, but doesn't work with all NFS implementations. */
	unsigned int use_excl_lock:1;
	/* Flush NFS attribute cache before stating files. */
	unsigned int nfs_flush:1;
	/* Use io_add_notify() to speed up finding out when an existing
	   dotlock is deleted */
	unsigned int use_io_notify:1;
};

enum dotlock_create_flags {
	/* If lock already exists, fail immediately */
	DOTLOCK_CREATE_FLAG_NONBLOCK		= 0x01,
	/* Don't actually create the lock file, only make sure it doesn't
	   exist. This is racy, so you shouldn't rely on it much. */
	DOTLOCK_CREATE_FLAG_CHECKONLY		= 0x02
};

enum dotlock_replace_flags {
	/* Check that lock file hasn't been overridden before renaming. */
	DOTLOCK_REPLACE_FLAG_VERIFY_OWNER	= 0x01,
	/* Don't close the file descriptor. */
	DOTLOCK_REPLACE_FLAG_DONT_CLOSE_FD	= 0x02
};

/* Create dotlock. Returns 1 if successful, 0 if timeout or -1 if error.
   When returning 0, errno is also set to EAGAIN. */
int file_dotlock_create(const struct dotlock_settings *set, const char *path,
			enum dotlock_create_flags flags,
			struct dotlock **dotlock_r);

/* Delete the dotlock file, ignoring any potential errors. */
void file_dotlock_delete(struct dotlock **dotlock);
/* Delete the dotlock file. Returns 1 if successful, 0 if the file had already
   been deleted or reused by someone else, -1 if I/O error. */
int file_dotlock_delete_verified(struct dotlock **dotlock);

/* Use dotlock as the new content for file. This provides read safety without
   locks, but it's not very good for large files. Returns fd for lock file.
   If locking timed out, returns -1 and errno = EAGAIN. */
int file_dotlock_open(const struct dotlock_settings *set, const char *path,
		      enum dotlock_create_flags flags,
		      struct dotlock **dotlock_r);
/* Like file_dotlock_open(), but use the given file permissions. */
int file_dotlock_open_mode(const struct dotlock_settings *set, const char *path,
			   enum dotlock_create_flags flags,
			   mode_t mode, uid_t uid, gid_t gid,
			   struct dotlock **dotlock_r);
int file_dotlock_open_group(const struct dotlock_settings *set, const char *path,
			    enum dotlock_create_flags flags,
			    mode_t mode, gid_t gid, const char *gid_origin,
			    struct dotlock **dotlock_r);
/* Replaces the file dotlock protects with the dotlock file itself. */
int file_dotlock_replace(struct dotlock **dotlock,
			 enum dotlock_replace_flags flags);
/* Update dotlock's mtime. If you're keeping the dotlock for a long time,
   it's a good idea to update it once in a while so others won't override it.
   If the timestamp is less than a second old, it's not updated. */
int file_dotlock_touch(struct dotlock *dotlock);
/* Returns TRUE if the lock is still ok, FALSE if it's been overridden. */
bool file_dotlock_is_locked(struct dotlock *dotlock);

/* Returns the lock file path. */
const char *file_dotlock_get_lock_path(struct dotlock *dotlock);

#endif
