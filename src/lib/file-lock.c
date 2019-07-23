/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "file-lock.h"
#include "file-dotlock.h"
#include "time-util.h"

#include <time.h>
#include <sys/stat.h>
#ifdef HAVE_FLOCK
#  include <sys/file.h>
#endif

struct file_lock {
	int fd;
	char *path;
	struct dotlock *dotlock;

	struct timeval locked_time;
	int lock_type;
	enum file_lock_method lock_method;
	bool unlink_on_free;
	bool close_on_free;
};

static struct timeval lock_wait_start;
static uint64_t file_lock_wait_usecs = 0;
static long long file_lock_slow_warning_usecs = -1;

static void file_lock_log_warning_if_slow(struct file_lock *lock);

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

	i_zero(&fl);
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
	char node_buf[MAX_INT_STRLEN * 3 + 2];
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
		if (str_array_length(args) < 8) {
			; /* don't continue from within a T_BEGIN {...} T_END */
		} else if (strcmp(args[5], node_buf) == 0) {
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

	if (timeout_secs != 0) {
		alarm(timeout_secs);
		file_lock_wait_start();
	}

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
		if (timeout_secs != 0) {
			alarm(0);
			file_lock_wait_end(path);
		}

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
		if (timeout_secs != 0) {
			alarm(0);
			file_lock_wait_end(path);
		}

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
	if (gettimeofday(&lock->locked_time, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");
	*lock_r = lock;
	return 1;
}

int file_lock_try_update(struct file_lock *lock, int lock_type)
{
	const char *error;
	int ret;

	ret = file_lock_do(lock->fd, lock->path, lock_type,
			   lock->lock_method, 0, &error);
	if (ret <= 0)
		return ret;
	file_lock_log_warning_if_slow(lock);
	lock->lock_type = lock_type;
	return 1;
}

void file_lock_set_unlink_on_free(struct file_lock *lock, bool set)
{
	lock->unlink_on_free = set;
}

void file_lock_set_close_on_free(struct file_lock *lock, bool set)
{
	lock->close_on_free = set;
}

struct file_lock *file_lock_from_dotlock(struct dotlock **dotlock)
{
	struct file_lock *lock;

	lock = i_new(struct file_lock, 1);
	lock->fd = -1;
	lock->path = i_strdup(file_dotlock_get_lock_path(*dotlock));
	lock->lock_type = F_WRLCK;
	lock->lock_method = FILE_LOCK_METHOD_DOTLOCK;
	if (gettimeofday(&lock->locked_time, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");
	lock->dotlock = *dotlock;

	*dotlock = NULL;
	return lock;
}

static void file_unlock_real(struct file_lock *lock)
{
	const char *error;

	if (file_lock_do(lock->fd, lock->path, F_UNLCK,
			 lock->lock_method, 0, &error) == 0) {
		/* this shouldn't happen */
		i_error("file_unlock(%s) failed: %m", lock->path);
	}
}

void file_unlock(struct file_lock **_lock)
{
	struct file_lock *lock = *_lock;

	*_lock = NULL;

	/* unlocking is unnecessary when the file is unlinked. or alternatively
	   the unlink() must be done before unlocking, because otherwise it
	   could be deleting the new lock. */
	i_assert(!lock->unlink_on_free);

	if (lock->dotlock == NULL)
		file_unlock_real(lock);
	file_lock_free(&lock);
}

static void file_try_unlink_locked(struct file_lock *lock)
{
	struct file_lock *temp_lock = NULL;
	struct stat st1, st2;
	const char *error;
	int ret;

	file_unlock_real(lock);
	ret = file_try_lock_error(lock->fd, lock->path, F_WRLCK,
				  lock->lock_method, &temp_lock, &error);
	if (ret < 0) {
		i_error("file_lock_free(): Unexpectedly failed to retry locking %s: %s",
			lock->path, error);
	} else if (ret == 0) {
		/* already locked by someone else */
	} else if (fstat(lock->fd, &st1) < 0) {
		/* not expected to happen */
		i_error("file_lock_free(): fstat(%s) failed: %m", lock->path);
	} else if (stat(lock->path, &st2) < 0) {
		if (errno != ENOENT)
			i_error("file_lock_free(): stat(%s) failed: %m", lock->path);
	} else if (st1.st_ino != st2.st_ino ||
		   !CMP_DEV_T(st1.st_dev, st2.st_dev)) {
		/* lock file was recreated already - don't delete it */
	} else {
		/* nobody was waiting on the lock - unlink it */
		i_unlink(lock->path);
	}
	file_lock_free(&temp_lock);
}

void file_lock_free(struct file_lock **_lock)
{
	struct file_lock *lock = *_lock;

	if (lock == NULL)
		return;

	*_lock = NULL;

	if (lock->dotlock != NULL)
		file_dotlock_delete(&lock->dotlock);
	if (lock->unlink_on_free)
		file_try_unlink_locked(lock);
	if (lock->close_on_free)
		i_close_fd(&lock->fd);

	file_lock_log_warning_if_slow(lock);
	i_free(lock->path);
	i_free(lock);
}

const char *file_lock_get_path(struct file_lock *lock)
{
	return lock->path;
}

void file_lock_set_path(struct file_lock *lock, const char *path)
{
	if (path != lock->path) {
		i_free(lock->path);
		lock->path = i_strdup(path);
	}
}

void file_lock_wait_start(void)
{
	i_assert(lock_wait_start.tv_sec == 0);

	if (gettimeofday(&lock_wait_start, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");
}

static void file_lock_wait_init_warning(void)
{
	const char *value;

	i_assert(file_lock_slow_warning_usecs == -1);

	value = getenv("FILE_LOCK_SLOW_WARNING_MSECS");
	if (value == NULL)
		file_lock_slow_warning_usecs = LLONG_MAX;
	else if (str_to_llong(value, &file_lock_slow_warning_usecs) == 0 &&
		 file_lock_slow_warning_usecs > 0) {
		file_lock_slow_warning_usecs *= 1000;
	} else {
		i_error("FILE_LOCK_SLOW_WARNING_MSECS: "
			"Invalid value '%s' - ignoring", value);
		file_lock_slow_warning_usecs = LLONG_MAX;
	}
}

static void file_lock_log_warning_if_slow(struct file_lock *lock)
{
	if (file_lock_slow_warning_usecs < 0)
		file_lock_wait_init_warning();
	if (file_lock_slow_warning_usecs == LLONG_MAX) {
		/* slowness checking is disabled */
		return;
	}
	if (lock->lock_type != F_WRLCK) {
		/* some shared locks can legitimately be kept for a long time.
		   don't warn about them. */
		return;
	}

	struct timeval now;
	if (gettimeofday(&now, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");

	int diff = timeval_diff_msecs(&now, &lock->locked_time);
	if (diff > file_lock_slow_warning_usecs/1000) {
		i_warning("Lock %s kept for %d.%03d secs", lock->path,
			  diff / 1000, diff % 1000);
	}
}

void file_lock_wait_end(const char *lock_name)
{
	struct timeval now;

	i_assert(lock_wait_start.tv_sec != 0);

	if (gettimeofday(&now, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");
	long long diff = timeval_diff_usecs(&now, &lock_wait_start);
	if (diff < 0) {
		/* time moved backwards */
		diff = 0;
	}
	if (diff > file_lock_slow_warning_usecs) {
		if (file_lock_slow_warning_usecs < 0)
			file_lock_wait_init_warning();
		if (diff > file_lock_slow_warning_usecs) {
			int diff_msecs = (diff + 999) / 1000;
			i_warning("Locking %s took %d.%03d secs", lock_name,
				  diff_msecs / 1000, diff_msecs % 1000);
		}
	}
	file_lock_wait_usecs += diff;
	lock_wait_start.tv_sec = 0;
}

uint64_t file_lock_wait_get_total_usecs(void)
{
	return file_lock_wait_usecs;
}
