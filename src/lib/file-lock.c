/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

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

int file_try_lock(int fd, const char *path, int lock_type,
		  enum file_lock_method lock_method,
		  struct file_lock **lock_r)
{
	return file_wait_lock(fd, path, lock_type, lock_method, 0, lock_r);
}

static int file_lock_do(int fd, const char *path, int lock_type,
			enum file_lock_method lock_method,
			unsigned int timeout_secs)
{
	int ret;

	i_assert(fd != -1);

	if (timeout_secs != 0)
		alarm(timeout_secs);

	switch (lock_method) {
	case FILE_LOCK_METHOD_FCNTL: {
#ifndef HAVE_FCNTL
		i_fatal("fcntl() locks not supported");
#else
		struct flock fl;
		const char *errstr;

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
			return 0;
		}

		if (errno == EINTR) {
			/* most likely alarm hit, meaning we timeouted.
			   even if not, we probably want to be killed
			   so stop blocking. */
			errno = EAGAIN;
			return 0;
		}
		errstr = errno != EACCES ? strerror(errno) :
			"File is locked by another process (EACCES)";
		i_error("fcntl(%s) locking failed for file %s: %s",
			lock_type == F_UNLCK ? "unlock" :
			lock_type == F_RDLCK ? "read-lock" : "write-lock",
			path, errstr);
		return -1;
#endif
	}
	case FILE_LOCK_METHOD_FLOCK: {
#ifndef HAVE_FLOCK
		i_fatal("flock() locks not supported");
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

		if (errno == EWOULDBLOCK || errno == EINTR) {
			/* a) locked by another process,
			   b) timeouted */
			return 0;
		}
		i_error("flock(%s) locking failed for file %s: %m",
			lock_type == F_UNLCK ? "unlock" :
			lock_type == F_RDLCK ? "read-lock" : "write-lock",
			path);
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
	struct file_lock *lock;
	int ret;

	ret = file_lock_do(fd, path, lock_type, lock_method, timeout_secs);
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
	return file_lock_do(lock->fd, lock->path, lock_type,
			    lock->lock_method, 0);
}

void file_unlock(struct file_lock **_lock)
{
	struct file_lock *lock = *_lock;

	*_lock = NULL;

	if (file_lock_do(lock->fd, lock->path, F_UNLCK,
			 lock->lock_method, 0) == 0) {
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
