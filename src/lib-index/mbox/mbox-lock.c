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

#ifdef HAVE_FLOCK
#  define USE_FLOCK
#endif

/* 0.1 .. 0.2msec */
#define LOCK_RANDOM_USLEEP_TIME (100000 + (unsigned int)rand() % 100000)

/* abort trying to get lock after 30 seconds */
#define MAX_LOCK_WAIT_SECONDS 30

/* remove lock after 10 mins */
#define STALE_LOCK_TIMEOUT (60*10)

#ifdef USE_FLOCK

static int mbox_lock_flock(MailIndex *index, const char *path, int fd, int set)
{
	if (flock(fd, set ? LOCK_EX : LOCK_UN) == -1) {
		index_file_set_syscall_error(index, path, "flock()");
		return FALSE;
	}

	return TRUE;
}

#else

static int mbox_lock_fcntl(MailIndex *index, const char *path, int fd, int set)
{
	struct flock fl;

	fl.l_type = set ? F_WRLCK : F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	while (fcntl(fd, F_SETLKW, &fl) == -1) {
		if (errno != EINTR) {
			index_file_set_syscall_error(index, path, "fcntl()");
			return FALSE;
		}
	}

	return TRUE;
}
#endif

static int mbox_lock_dotlock(MailIndex *index, const char *path, int set)
{
	struct stat st;
	time_t now, max_wait_time;
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
	max_wait_time = time(NULL) + MAX_LOCK_WAIT_SECONDS;
	do {
		now = time(NULL);

		if (stat(path, &st) == 0) {
			/* lock exists, see if it's too old */
			if (now > st.st_ctime + STALE_LOCK_TIMEOUT && 
			    unlink(path) < 0 && errno != ENOENT) {
				index_file_set_syscall_error(index, path,
							     "unlink()");
				break;
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

int mbox_lock(MailIndex *index, const char *path, int fd)
{
	i_assert(fd >= 0);

	if (++index->mbox_locks > 1)
		return TRUE;

#ifdef USE_FLOCK
	if (!mbox_lock_flock(index, path, fd, TRUE))
		return FALSE;
#else
	if (!mbox_lock_fcntl(index, path, fd, TRUE))
		return FALSE;
#endif
	if (!mbox_lock_dotlock(index, path, TRUE))
		return FALSE;

	return TRUE;
}

int mbox_unlock(MailIndex *index, const char *path, int fd)
{
	i_assert(fd >= 0);

	if (--index->mbox_locks > 0)
		return TRUE;

#ifdef USE_FLOCK
	if (!mbox_lock_flock(index, path, fd, FALSE))
		return FALSE;
#else
	if (!mbox_lock_fcntl(index, path, fd, FALSE))
		return FALSE;
#endif
	if (!mbox_lock_dotlock(index, path, FALSE))
		return FALSE;

	return TRUE;
}
