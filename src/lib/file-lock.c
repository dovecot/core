/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "file-lock.h"

#include <time.h>
#include <sys/stat.h>
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

static const char *
file_lock_find_fcntl(int lock_fd, int lock_type)
{
	struct flock fl;

	memset(&fl, 0, sizeof(fl));
	fl.l_type = lock_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(lock_fd, F_GETLK, &fl) < 0 ||
	    fl.l_type == F_UNLCK || fl.l_pid == -1 || fl.l_pid == 0)
		return "";
	return t_strdup_printf(" (%s lock held by pid %ld)",
		fl.l_type == F_RDLCK ? "READ" : "WRITE", (long)fl.l_pid);
}

static const char *
file_lock_find_proc_locks(int lock_fd ATTR_UNUSED)
{
	/* do anything except Linux support this? don't bother trying it for
	   OSes we don't know about. */
#ifdef __linux__
	static bool have_proc_locks = TRUE;
	struct stat st;
	char node_buf[MAX_INT_STRLEN*3 + 2 + 1];
	struct istream *input;
	const char *line, *lock_type = "";
	pid_t pid = 0;
	int fd;

	if (!have_proc_locks)
		return NULL;

	if (fstat(lock_fd, &st) < 0)
		return "";
	i_snprintf(node_buf, sizeof(node_buf), "%02x:%02x:%llu",
		   major(st.st_dev), minor(st.st_dev),
		   (unsigned long long)st.st_ino);
	fd = open("/proc/locks", O_RDONLY);
	if (fd == -1) {
		have_proc_locks = FALSE;
		return "";
	}
	input = i_stream_create_fd_autoclose(&fd, 512);
	while (pid == 0 && (line = i_stream_read_next_line(input)) != NULL) T_BEGIN {
		const char *const *args = t_strsplit_spaces(line, " ");

		/* number: FLOCK/POSIX ADVISORY READ/WRITE pid
		   major:minor:inode region-start region-end */
		if (str_array_length(args) < 8)
			continue;
		if (strcmp(args[5], node_buf) == 0) {
			lock_type = strcmp(args[3], "READ") == 0 ?
				"READ" : "WRITE";
			if (str_to_pid(args[4], &pid) < 0)
				pid = 0;
		}
	} T_END;
	i_stream_destroy(&input);
	if (pid == 0) {
		/* not found */
		return "";
	}
	if (pid == getpid())
		return " (BUG: lock is held by our own process)";
	return t_strdup_printf(" (%s lock held by pid %ld)", lock_type, (long)pid);
#else
	return "";
#endif
}

const char *file_lock_find(int lock_fd, enum file_lock_method lock_method,
			   int lock_type)
{
	const char *ret;

	if (lock_method == FILE_LOCK_METHOD_FCNTL) {
		ret = file_lock_find_fcntl(lock_fd, lock_type);
		if (ret[0] != '\0')
			return ret;
	}
	return file_lock_find_proc_locks(lock_fd);
}

static bool err_is_lock_timeout(time_t started, unsigned int timeout_secs)
{
	/* if EINTR took at least timeout_secs-1 number of seconds,
	   assume it was the alarm. otherwise log EINTR failure.
	   (We most likely don't want to retry EINTR since a signal
	   means somebody wants us to stop blocking). */
	return errno == EINTR &&
		(unsigned long)(time(NULL) - started + 1) >= timeout_secs;
}

static int file_lock_do(int fd, const char *path, int lock_type,
			enum file_lock_method lock_method,
			unsigned int timeout_secs, const char **error_r)
{
	const char *lock_type_str;
	time_t started = time(NULL);
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

		ret = fcntl(fd, timeout_secs != 0 ? F_SETLKW : F_SETLK, &fl);
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

		if (err_is_lock_timeout(started, timeout_secs)) {
			errno = EAGAIN;
			*error_r = t_strdup_printf(
				"fcntl(%s, %s, F_SETLKW) locking failed: "
				"Timed out after %u seconds%s",
				path, lock_type_str, timeout_secs,
				file_lock_find(fd, lock_method, lock_type));
			return 0;
		}
		*error_r = t_strdup_printf("fcntl(%s, %s, %s) locking failed: %m",
			path, lock_type_str, timeout_secs == 0 ? "F_SETLK" : "F_SETLKW");
		if (errno == EDEADLK)
			i_panic("%s%s", *error_r, file_lock_find(fd, lock_method, lock_type));
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
		if (err_is_lock_timeout(started, timeout_secs)) {
			errno = EAGAIN;
			*error_r = t_strdup_printf("flock(%s, %s) failed: "
				"Timed out after %u seconds%s",
				path, lock_type_str, timeout_secs,
				file_lock_find(fd, lock_method, lock_type));
			return 0;
		}
		*error_r = t_strdup_printf("flock(%s, %s) failed: %m",
					   path, lock_type_str);
		if (errno == EDEADLK)
			i_panic("%s%s", *error_r, file_lock_find(fd, lock_method, lock_type));
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
