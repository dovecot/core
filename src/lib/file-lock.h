#ifndef FILE_LOCK_H
#define FILE_LOCK_H

#include <unistd.h>
#include <fcntl.h>

#define DEFAULT_LOCK_TIMEOUT 120

struct file_lock;

enum file_lock_method {
	FILE_LOCK_METHOD_FCNTL,
	FILE_LOCK_METHOD_FLOCK,
	FILE_LOCK_METHOD_DOTLOCK
};

/* Parse lock method from given string. Returns TRUE if ok,
   FALSE if name is unknown. */
bool file_lock_method_parse(const char *name, enum file_lock_method *method_r);

/* Lock the file. Returns 1 if successful, 0 if file is already locked,
   or -1 if error. lock_type is F_WRLCK or F_RDLCK. */
int file_try_lock(int fd, const char *path, int lock_type,
		  enum file_lock_method lock_method,
		  struct file_lock **lock_r);
/* Like lock_try_lock(), but return 0 only after having tried to lock for
   timeout_secs. */
int file_wait_lock(int fd, const char *path, int lock_type,
		   enum file_lock_method lock_method,
		   unsigned int timeout_secs,
		   struct file_lock **lock_r);
/* Change the lock type. */
int file_lock_try_update(struct file_lock *lock, int lock_type);

/* Unlock and free the lock. */
void file_unlock(struct file_lock **lock);
/* Free the lock without unlocking it (because you're closing the fd anyway). */
void file_lock_free(struct file_lock **lock);

#endif
