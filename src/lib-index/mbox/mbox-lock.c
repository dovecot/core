/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef HAVE_FLOCK
#  include <sys/file.h>
#endif

/* 0.1 .. 0.2msec */
#define LOCK_RANDOM_USLEEP_TIME (100000 + (unsigned int)rand() % 100000)

/* lock methods to use in wanted order */
#define DEFAULT_LOCK_METHODS "dotlock fcntl flock"
/* lock timeout */
#define DEFAULT_LOCK_TIMEOUT 300
/* assume stale dotlock if mbox file hasn't changed for n seconds */
#define DEFAULT_DOTLOCK_CHANGE_TIMEOUT 30

static int lock_settings_initialized = FALSE;
static int use_dotlock, use_fcntl_lock, use_flock, fcntl_before_flock;
static int use_read_dotlock, lock_timeout, dotlock_change_timeout;

static void mbox_init_lock_settings(void)
{
	const char *str;
	char *const *lock;

        use_dotlock = use_fcntl_lock = use_flock = fcntl_before_flock = FALSE;

	str = getenv("MBOX_LOCKS");
	if (str == NULL) str = DEFAULT_LOCK_METHODS;
	for (lock = t_strsplit(str, " "); *lock != NULL; lock++) {
		if (strcasecmp(*lock, "dotlock") == 0)
			use_dotlock = TRUE;
		else if (strcasecmp(*lock, "fcntl") == 0) {
			use_fcntl_lock = TRUE;
			fcntl_before_flock = use_flock == FALSE;
		} else if (strcasecmp(*lock, "flock") == 0)
			use_flock = TRUE;
		else
			i_fatal("MBOX_LOCKS: Invalid value %s", *lock);
	}

	use_read_dotlock = getenv("MBOX_READ_DOTLOCK") != NULL;

	str = getenv("MBOX_LOCK_TIMEOUT");
	lock_timeout = str == NULL ? DEFAULT_LOCK_TIMEOUT : atoi(str);

	str = getenv("MBOX_DOTLOCK_CHANGE_TIMEOUT");
	dotlock_change_timeout = str == NULL ?
		DEFAULT_DOTLOCK_CHANGE_TIMEOUT : atoi(str);

        lock_settings_initialized = TRUE;
}

#ifdef HAVE_FLOCK
static int mbox_lock_flock(MailIndex *index, MailLockType lock_type,
			   time_t max_wait_time)
{
	if (lock_type == MAIL_LOCK_EXCLUSIVE)
		lock_type = LOCK_EX;
	else if (lock_type == MAIL_LOCK_SHARED)
		lock_type = LOCK_SH;
	else
		lock_type = LOCK_UN;

	while (flock(index->mbox_fd, lock_type | LOCK_NB) < 0) {
		if (errno != EWOULDBLOCK) {
			index_file_set_syscall_error(index, index->mbox_path,
						     "flock()");
			return FALSE;
		}

		if (max_wait_time != 0 && time(NULL) >= max_wait_time) {
			errno = EAGAIN;
			return FALSE;
		}

		usleep(LOCK_RANDOM_USLEEP_TIME);
	}

	return TRUE;
}
#endif

static int mbox_lock_fcntl(MailIndex *index, MailLockType lock_type,
			   time_t max_wait_time)
{
	struct flock fl;

	fl.l_type = MAIL_LOCK_TO_FLOCK(lock_type);
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	while (fcntl(index->mbox_fd, F_SETLKW, &fl) == -1) {
		if (errno != EINTR) {
			index_file_set_syscall_error(index, index->mbox_path,
						     "fcntl()");
			return FALSE;
		}

		if (max_wait_time != 0 && time(NULL) >= max_wait_time) {
			errno = EAGAIN;
			return FALSE;
		}
	}

	return TRUE;
}

static int mbox_lock_dotlock(MailIndex *index, const char *path,
			     time_t max_wait_time, int checkonly)
{
	struct stat st;
	time_t now, last_change, last_mtime;
	off_t last_size;
	int fd;

	path = t_strconcat(path, ".lock", NULL);

	/* don't bother with the temp files as we'd just leave them lying
	   around. besides, postfix also relies on O_EXCL working so we
	   might as well. */
	last_change = time(NULL); last_size = 0; last_mtime = 0;
	do {
		now = time(NULL);

		if (stat(path, &st) == 0) {
			/* see if there's been any changes in mbox */
			if (stat(index->mbox_path, &st) < 0) {
				mbox_set_syscall_error(index, "stat()");
				break;
			}

			if (last_size != st.st_size ||
			    last_mtime != st.st_mtime) {
				last_change = now;
				last_size = st.st_size;
				last_mtime = st.st_mtime;
			}

			if (now > last_change + dotlock_change_timeout) {
				/* no changes for a while, assume stale lock */
				if (unlink(path) < 0 && errno != ENOENT) {
					index_file_set_syscall_error(
						index, path, "unlink()");
					break;
				}
				continue;
			}

			usleep(LOCK_RANDOM_USLEEP_TIME);
			continue;
		}

		if (checkonly) {
			/* we only wanted to check that the .lock file
			   doesn't exist. This is racy of course, but I don't
			   think there's any better way to do it really.
			   The fcntl/flock later does the real locking, so
			   problem comes only when someone uses only dotlock
			   locking, and we can't fix that without dotlocking
			   ourself (which we didn't want to do here) */
			return TRUE;
		}

		fd = open(path, O_WRONLY | O_EXCL | O_CREAT, 0);
		if (fd != -1) {
			/* got it */
			if (fstat(fd, &st) < 0) {
				index_file_set_syscall_error(index, path,
							     "fstat()");
				(void)close(fd);
				return FALSE;
			}

			index->mbox_dotlock_dev = st.st_dev;
			index->mbox_dotlock_ino = st.st_ino;

			if (close(fd) < 0) {
				index_file_set_syscall_error(index, path,
							     "close()");
				return FALSE;
			}
			return TRUE;
		}

		if (errno != EEXIST) {
			index_file_set_syscall_error(index, path, "open()");
			return FALSE;
		}
	} while (now < max_wait_time);

	index_set_error(index, "Timeout while waiting for release of mbox "
			"dotlock %s", path);
	return FALSE;
}

static int mbox_unlock_dotlock(MailIndex *index, const char *path)
{
	struct stat st;
	dev_t old_dev;
	ino_t old_ino;

	path = t_strconcat(path, ".lock", NULL);

        old_dev = index->mbox_dotlock_dev;
        old_ino = index->mbox_dotlock_ino;

        index->mbox_dotlock_dev = 0;
        index->mbox_dotlock_ino = 0;

	if (stat(path, &st) < 0) {
		if (errno == ENOENT)
			return TRUE; /* doesn't exist anymore, ignore */

		index_file_set_syscall_error(index, path, "stat()");
		return FALSE;
	}

	/* make sure it's still our dotlock */
	if (old_dev != st.st_dev || old_ino != st.st_ino) {
		index_set_error(index,
			"Warning: Our dotlock file %s was overridden", path);
		return FALSE;
	}

	if (unlink(path) < 0 && errno != ENOENT)
		return index_file_set_syscall_error(index, path, "unlink()");

	return TRUE;
}

static int mbox_file_locks(MailIndex *index, time_t max_wait_time)
{
	if (use_fcntl_lock && fcntl_before_flock) {
		if (!mbox_lock_fcntl(index, index->mbox_lock_type,
				     max_wait_time))
			return FALSE;
	}
#ifdef HAVE_FLOCK
	if (use_flock) {
		if (!mbox_lock_flock(index, index->mbox_lock_type,
				     max_wait_time))
			return FALSE;
	}
#endif
	if (use_fcntl_lock && !fcntl_before_flock) {
		if (!mbox_lock_fcntl(index, index->mbox_lock_type,
				     max_wait_time))
			return FALSE;
	}
	return TRUE;
}

int mbox_lock(MailIndex *index, MailLockType lock_type)
{
	struct stat st;
	time_t max_wait_time;

	/* index must be locked before mbox file, to avoid deadlocks */
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	/* allow only unlock -> shared/exclusive or exclusive -> shared */
	i_assert(lock_type == MAIL_LOCK_SHARED ||
		 lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(lock_type != MAIL_LOCK_EXCLUSIVE ||
		 index->mbox_lock_type != MAIL_LOCK_SHARED);

	if (index->mbox_lock_type == lock_type)
		return TRUE;

	if (!lock_settings_initialized)
                mbox_init_lock_settings();

	max_wait_time = time(NULL) + lock_timeout;

	/* make .lock file first to protect overwriting the file */
	if (use_dotlock && index->mbox_dotlock_ino == 0) {
		if (!mbox_lock_dotlock(index, index->mbox_path, max_wait_time,
				       lock_type == MAIL_LOCK_SHARED &&
				       !use_read_dotlock))
			return FALSE;
	}

	/* now we need to have the file itself locked. open it if needed. */
	if (stat(index->mbox_path, &st) < 0)
		return mbox_set_syscall_error(index, "stat()");

	if (st.st_dev != index->mbox_dev || st.st_ino != index->mbox_ino)
		mbox_file_close_fd(index);

	if (index->mbox_fd == -1) {
		if (!mbox_file_open(index)) {
			(void)mbox_unlock(index);
			return FALSE;
		}
	}

	index->mbox_lock_type = lock_type;
	if (!mbox_file_locks(index, max_wait_time)) {
		(void)mbox_unlock(index);
		return FALSE;
	}

	return TRUE;
}

int mbox_unlock(MailIndex *index)
{
	int failed;

	index->mbox_lock_counter++;

	if (index->mbox_lock_type == MAIL_LOCK_UNLOCK)
		return TRUE;

	failed = FALSE;
	if (index->mbox_fd != -1) {
#ifdef HAVE_FLOCK
		if (use_flock && !mbox_lock_flock(index, MAIL_LOCK_UNLOCK, 0))
			failed = TRUE;
#endif
		if (use_fcntl_lock &&
		    !mbox_lock_fcntl(index, MAIL_LOCK_UNLOCK, 0))
			failed = TRUE;
	}

	if (index->mbox_dotlock_ino != 0) {
		if (!mbox_unlock_dotlock(index, index->mbox_path))
			failed = TRUE;
	}

	/* make sure we don't keep mmap() between locks - there could have
	   been changes to file size which would break things. or actually
	   it'd break only if file was shrinked+grown back to exact size,
	   but still possible :) */
	mbox_file_close_inbuf(index);

	index->mbox_lock_type = MAIL_LOCK_UNLOCK;
	return !failed;
}
