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

/* assume stale dotlock if mbox file hasn't changed for 5 seconds */
#define MAX_UNCHANGED_LOCK_WAIT 5

/* abort trying to get lock after 30 seconds */
#define MAX_LOCK_WAIT 30

/* remove lock after 10 mins */
#define STALE_LOCK_TIMEOUT (60*10)

#ifdef HAVE_FLOCK
static int mbox_lock_flock(MailIndex *index, MailLockType lock_type)
{
	if (lock_type == MAIL_LOCK_EXCLUSIVE)
		lock_type = LOCK_EX;
	else if (lock_type == MAIL_LOCK_SHARED)
		lock_type = LOCK_SH;
	else
		lock_type = LOCK_UN;

	if (flock(index->mbox_fd, lock_type) < 0)
		return index_file_set_syscall_error(index, index->mbox_path,
						    "flock()");

	return TRUE;
}
#endif

static int mbox_lock_fcntl(MailIndex *index, MailLockType lock_type)
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
	}

	return TRUE;
}

static int mbox_lock_dotlock(MailIndex *index, const char *path, int set)
{
	struct stat st;
	time_t now, max_wait_time, last_change, last_mtime;
	off_t last_size;
	int fd;

	path = t_strconcat(path, ".lock", NULL);
	if (!set) {
		if (unlink(path) == 0 || errno == ENOENT)
			return TRUE;

		return index_file_set_syscall_error(index, path, "unlink()");
	}

	/* don't bother with the temp files as we'd just leave them lying
	   around. besides, postfix also relies on O_EXCL working so we
	   might as well. */
	max_wait_time = time(NULL) + MAX_LOCK_WAIT;
	last_change = time(NULL); last_size = 0; last_mtime = 0;
	do {
		now = time(NULL);

		if (stat(path, &st) == 0) {
			/* lock exists, see if it's too old */
			if (now > st.st_ctime + STALE_LOCK_TIMEOUT) {
				if (unlink(path) < 0 && errno != ENOENT) {
					index_file_set_syscall_error(
						index, path, "unlink()");
					break;
				}
				continue;
			}

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

			if (now > last_change + MAX_UNCHANGED_LOCK_WAIT) {
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

		fd = open(path, O_WRONLY | O_EXCL | O_CREAT, 0);
		if (fd != -1) {
			/* got it */
			if (close(fd) < 0) {
				index_file_set_syscall_error(index, path,
							     "close()");
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

int mbox_lock(MailIndex *index, MailLockType lock_type)
{
	struct stat st;

	/* index must be locked before mbox file, to avoid deadlocks */
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	/* allow only unlock -> shared/exclusive or exclusive -> shared */
	i_assert(lock_type == MAIL_LOCK_SHARED ||
		 lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(lock_type != MAIL_LOCK_EXCLUSIVE ||
		 index->mbox_lock_type != MAIL_LOCK_SHARED);

	if (index->mbox_lock_type == lock_type)
		return TRUE;

	/* make .lock file first to protect overwriting the file */
	if (index->mbox_lock_type == MAIL_LOCK_UNLOCK) {
		if (!mbox_lock_dotlock(index, index->mbox_path, TRUE))
			return FALSE;
	}

	/* now we need to have the file itself locked. open it if needed. */
	do {
		if (stat(index->mbox_path, &st) < 0)
			return mbox_set_syscall_error(index, "stat()");

		if (st.st_dev != index->mbox_dev ||
		    st.st_ino != index->mbox_ino)
			mbox_file_close_fd(index);

		if (index->mbox_fd == -1) {
			if (!mbox_file_open(index))
				break;
		}

		if (!mbox_lock_fcntl(index, index->mbox_lock_type))
			break;
#ifdef HAVE_FLOCK
		if (!mbox_lock_flock(index, index->mbox_lock_type))
			break;
#endif
		index->mbox_lock_type = lock_type;
		return TRUE;
	} while (0);

	if (index->mbox_lock_type == MAIL_LOCK_UNLOCK)
		(void)mbox_lock_dotlock(index, index->mbox_path, FALSE);

	return FALSE;
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
		if (!mbox_lock_flock(index, MAIL_LOCK_UNLOCK))
			failed = TRUE;
#endif
		if (!mbox_lock_fcntl(index, MAIL_LOCK_UNLOCK))
			failed = TRUE;
	}

	if (!mbox_lock_dotlock(index, index->mbox_path, FALSE))
		failed = TRUE;

	/* make sure we don't keep mmap() between locks - there could have
	   been changes to file size which would break things. or actually
	   it'd break only if file was shrinked+grown back to exact size,
	   but still possible :) */
	mbox_file_close_inbuf(index);

	index->mbox_lock_type = MAIL_LOCK_UNLOCK;
	return !failed;
}
