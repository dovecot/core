#ifndef FILE_LOCK_H
#define FILE_LOCK_H

#include <unistd.h>
#include <fcntl.h>

struct file_lock;
struct dotlock;

enum file_lock_method {
	FILE_LOCK_METHOD_FCNTL,
	FILE_LOCK_METHOD_FLOCK,
	FILE_LOCK_METHOD_DOTLOCK
};

struct file_lock_settings {
	enum file_lock_method lock_method;

	/* When the lock is freed, unlink() the file automatically, unless other
	   processes are already waiting on the lock. This can be useful for
	   files that are only created to exist as lock files. */
	bool unlink_on_free:1;
	/* When the lock is freed, close the fd automatically. This can
	   be useful for files that are only created to exist as lock files. */
	bool close_on_free:1;
	/* Do not panic when the kernel returns EDEADLK while acquiring the
	   lock. */
	bool allow_deadlock:1;
};

/* Parse lock method from given string. Returns TRUE if ok,
   FALSE if name is unknown. */
bool file_lock_method_parse(const char *name, enum file_lock_method *method_r);
/* Convert lock method to string. */
const char *file_lock_method_to_str(enum file_lock_method method);

/* Lock the file. Returns 1 if successful, 0 if file is already locked,
   or -1 if error. lock_type is F_WRLCK or F_RDLCK. */
int file_try_lock(int fd, const char *path, int lock_type,
		  const struct file_lock_settings *set,
		  struct file_lock **lock_r, const char **error_r);
/* Like lock_try_lock(), but return 0 only after having tried to lock for
   timeout_secs. */
int file_wait_lock(int fd, const char *path, int lock_type,
		   const struct file_lock_settings *set,
		   unsigned int timeout_secs,
		   struct file_lock **lock_r, const char **error_r);
/* Change the lock type. WARNING: This isn't an atomic operation!
   The result is the same as file_unlock() + file_try_lock(). */
int file_lock_try_update(struct file_lock *lock, int lock_type);
/* When the lock is freed, unlink() the file automatically, unless other
   processes are already waiting on the lock. This can be useful for files that
   are only created to exist as lock files. */
void file_lock_set_unlink_on_free(struct file_lock *lock, bool set);
/* When the lock is freed, close the fd automatically. This can
   be useful for files that are only created to exist as lock files. */
void file_lock_set_close_on_free(struct file_lock *lock, bool set);

/* Convert dotlock into file_lock, which can be deleted with either
   file_unlock() or file_lock_free(). */
struct file_lock *file_lock_from_dotlock(struct dotlock **dotlock);

/* Unlock and free the lock. */
void file_unlock(struct file_lock **lock);
/* Free the lock without unlocking it (because you're closing the fd anyway). */
void file_lock_free(struct file_lock **lock);

/* Returns the path given as parameter to file_*lock*(). */
const char *file_lock_get_path(struct file_lock *lock);
/* Update lock file's path (after it gets renamed by the caller). This is
   useful mainly together with file_lock_set_unlink_on_free(). */
void file_lock_set_path(struct file_lock *lock, const char *path);

/* Returns human-readable string containing the process that has the file
   currently locked. Returns "" if unknown, otherwise " (string)". */
const char *file_lock_find(int lock_fd, enum file_lock_method lock_method,
			   int lock_type);

/* Track the duration of a lock wait. */
void file_lock_wait_start(void);
void file_lock_wait_end(const char *lock_name);
/* Return how many microseconds has been spent on lock waiting. */
uint64_t file_lock_wait_get_total_usecs(void);

#endif
