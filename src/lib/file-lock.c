/* Copyright (c) 2002-2014 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "file-lock.h"

#ifdef HAVE_FLOCK
#  include <sys/file.h>
#endif

struct file_lock {
	int fd;
	char *path;

	int lock_type;
	enum file_lock_method lock_method;
};

bool file_lock_method_parse(const char *name, enum file_lock_method *method_r)
{
	if (strcasecmp(name, "fcntl") == 0)
		*method_r = FILE_LOCK_METHOD_FCNTL;
	else if (strcasecmp(name, "flock") == 0)
		*method_r = FILE_LOCK_METHOD_FLOCK;
	else if (strcasecmp(name, "dotlock") == 0)
		*method_r = FILE_LOCK_METHOD_DOTLOCK;
	else
		return FALSE;
	return TRUE;
}

const char *file_lock_method_to_str(enum file_lock_method method)
{
	switch (method) {
	case FILE_LOCK_METHOD_FCNTL:
		return "fcntl";
	case FILE_LOCK_METHOD_FLOCK:
		return "flock";
	case FILE_LOCK_METHOD_DOTLOCK:
		return "dotlock";
	}
	i_unreached();
}

int file_try_lock(int fd, const char *path, int lock_type,
		  enum file_lock_method lock_method,
		  struct file_lock **lock_r)
{
	return file_wait_lock(fd, path, lock_type, lock_method, 0, lock_r);
}

int file_try_lock_error(int fd, const char *path, int lock_type,
			enum file_lock_method lock_method,
			struct file_lock **lock_r, const char **error_r)
{
	return file_wait_lock_error(fd, path, lock_type, lock_method, 0,
				    lock_r, error_r);
}

static int file_lock_do(int fd, const char *path, int lock_type,
			enum file_lock_method lock_method,
			unsigned int timeout_secs, const char **error_r)
{
	const char *lock_type_str;
	int ret;

	i_assert(fd != -1);

	if (timeout_secs != 0)
		alarm(timeout_secs);

	lock_type_str = lock_type == F_UNLCK ? "unlock" :
		(lock_type == F_RDLCK ? "read-lock" : "write-lock");

	switch (lock_method) {
	case FILE_LOCK_METHOD_FCNTL: {
#ifndef HAVE_FCNTL
		*error_r = t_strdup_printf(
			"Can't lock file %s: fcntl() locks not supported", path);
		return -1;
#else
		struct flock fl;

		fl.l_type = lock_type;
		fl.l_whence = SEEK_SET;
		fl.l_start = 0;
		fl.l_len = 0;

		ret = fcntl(fd, timeout_secs ? F_SETLKW : F_SETLK, &fl);
		if (timeout_secs != 0) alarm(0);

		if (ret == 0)
			break;

		if (timeout_secs == 0 &&
		    (errno == EACCES || errno == EAGAIN)) {
			/* locked by another process */
			*error_r = t_strdup_printf(
				"fcntl(%s, %s, F_SETLK) locking failed: %m "
				"(File is already locked)", path, lock_type_str);
			return 0;
		}

		if (errno == EINTR) {
			/* most likely alarm hit, meaning we timeouted.
			   even if not, we probably want to be killed
			   so stop blocking. */
			errno = EAGAIN;
			*error_r = t_strdup_printf(
				"fcntl(%s, %s, F_SETLKW) locking failed: "
				"Timed out after %u seconds",
				path, lock_type_str, timeout_secs);
			return 0;
		}
		*error_r = t_strdup_printf("fcntl(%s, %s, %s) locking failed: %m",
			path, lock_type_str, timeout_secs == 0 ? "F_SETLK" : "F_SETLKW");
		return -1;
#endif
	}
	case FILE_LOCK_METHOD_FLOCK: {
#ifndef HAVE_FLOCK
		*error_r = t_strdup_printf(
			"Can't lock file %s: flock() not supported", path);
		return -1;
#else
		int operation = timeout_secs != 0 ? 0 : LOCK_NB;

		switch (lock_type) {
		case F_RDLCK:
			operation |= LOCK_SH;
			break;
		case F_WRLCK:
			operation |= LOCK_EX;
			break;
		case F_UNLCK:
			operation |= LOCK_UN;
			break;
		}

		ret = flock(fd, operation);
		if (timeout_secs != 0) alarm(0);

		if (ret == 0)
			break;

		if (timeout_secs == 0 && errno == EWOULDBLOCK) {
			/* locked by another process */
			*error_r = t_strdup_printf(
				"flock(%s, %s) failed: %m "
				"(File is already locked)", path, lock_type_str);
			return 0;
		}
		if (errno == EINTR) {
			errno = EAGAIN;
			*error_r = t_strdup_printf("flock(%s, %s) failed: "
				"Timed out after %u seconds",
				path, lock_type_str, timeout_secs);
			return 0;
		}
		*error_r = t_strdup_printf("flock(%s, %s) failed: %m",
					   path, lock_type_str);
		return -1;
#endif
	}
	case FILE_LOCK_METHOD_DOTLOCK:
		/* we shouldn't get here */
		i_unreached();
	}

	return 1;
}

int file_wait_lock(int fd, const char *path, int lock_type,
		   enum file_lock_method lock_method,
		   unsigned int timeout_secs,
		   struct file_lock **lock_r)
{
	const char *error;
	int ret;

	ret = file_wait_lock_error(fd, path, lock_type, lock_method,
				   timeout_secs, lock_r, &error);
	if (ret < 0)
		i_error("%s", error);
	return ret;
}

int file_wait_lock_error(int fd, const char *path, int lock_type,
			 enum file_lock_method lock_method,
			 unsigned int timeout_secs,
			 struct file_lock **lock_r, const char **error_r)
{
	struct file_lock *lock;
	int ret;

	ret = file_lock_do(fd, path, lock_type, lock_method, timeout_secs, error_r);
	if (ret <= 0)
		return ret;

	lock = i_new(struct file_lock, 1);
	lock->fd = fd;
	lock->path = i_strdup(path);
	lock->lock_type = lock_type;
	lock->lock_method = lock_method;
	*lock_r = lock;
	return 1;
}

int file_lock_try_update(struct file_lock *lock, int lock_type)
{
	const char *error;

	return file_lock_do(lock->fd, lock->path, lock_type,
			    lock->lock_method, 0, &error);
}

void file_unlock(struct file_lock **_lock)
{
	struct file_lock *lock = *_lock;
	const char *error;

	*_lock = NULL;

	if (file_lock_do(lock->fd, lock->path, F_UNLCK,
			 lock->lock_method, 0, &error) == 0) {
		/* this shouldn't happen */
		i_error("file_unlock(%s) failed: %m", lock->path);
	}

	file_lock_free(&lock);
}

void file_lock_free(struct file_lock **_lock)
{
	struct file_lock *lock = *_lock;

	*_lock = NULL;

	i_free(lock->path);
	i_free(lock);
}
