/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "unlink-lockfiles.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-lockdir.h"

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define DIRLOCK_FILE_PREFIX ".imap.dirlock"

/* 0.1 .. 0.2msec */
#define LOCK_RANDOM_USLEEP_TIME (100000 + (unsigned int)rand() % 100000)

/* The dirlock should be used only while creating the index file. After the
   header is written, the file itself should be locked and dirlock dropped
   before index is built. So, this value shouldn't be very large, probably
   even a few seconds would more than enough but we'll use a safe 10 seconds
   by default. */
#define MAX_LOCK_WAIT_SECONDS 10

/* Non-local locks have a life time of 30 minutes, just to be sure that
   small clock differences won't break things. */
#define NFS_LOCK_TIMEOUT (60*30)

static int mail_index_cleanup_dir_locks(const char *dir)
{
	const char *hostprefix, *path;
	struct stat st;

	hostprefix = t_strconcat(DIRLOCK_FILE_PREFIX ".",
				 my_hostname, ".", NULL);

	unlink_lockfiles(dir, hostprefix, DIRLOCK_FILE_PREFIX ".",
			 time(NULL) - NFS_LOCK_TIMEOUT);

	/* if hard link count has dropped to 1, we've unlocked the file */
	path = t_strconcat(dir, "/" DIRLOCK_FILE_PREFIX, NULL);
	if (stat(path, &st) == 0 && st.st_nlink == 1) {
		/* only itself, safe to delete */
		(void)unlink(path);
		return TRUE;
	}

	return FALSE;
}

static int mail_index_unlock_dir(MailIndex *index, const char *private_path,
				 const char *lockpath)
{
	struct stat st, lockst;

	if (stat(lockpath, &st) < 0)
		return index_file_set_syscall_error(index, lockpath, "stat()");

	if (st.st_nlink > 1) {
		/* make sure we're really the one who's locked it */
		if (stat(private_path, &lockst) < 0) {
			return index_file_set_syscall_error(index, private_path,
							    "stat()");
		}

		if (st.st_dev != lockst.st_dev ||
		    st.st_ino != lockst.st_ino) {
			index_set_error(index, "Unlocking file %s failed: "
					"we're not the lock owner "
					"(%lu,%lu vs %lu,%lu)", lockpath,
					(unsigned long) st.st_dev,
					(unsigned long) st.st_ino,
					(unsigned long) lockst.st_dev,
					(unsigned long) lockst.st_ino);
			return FALSE;
		}
	}

	/* first unlink the actual lock file */
	if (unlink(lockpath) < 0) {
		index_file_set_syscall_error(index, lockpath, "unlink()");
		return FALSE;
	}

	if (unlink(private_path) < 0) {
		/* non-fatal */
		index_file_set_syscall_error(index, private_path, "unlink()");
	}
	return TRUE;
}

int mail_index_lock_dir(MailIndex *index, MailLockType lock_type)
{
	struct stat st;
	const char *private_path, *lockpath;
	int fd, orig_errno, first;
	time_t max_wait_time;

	i_assert(lock_type == MAIL_LOCK_EXCLUSIVE ||
		 lock_type == MAIL_LOCK_UNLOCK);

	hostpid_init();

	/* use .dirlock.host.pid as our lock indicator file and
	   .dirlock as the real lock */
	private_path = t_strconcat(index->dir, "/" DIRLOCK_FILE_PREFIX ".",
				   my_hostname, ".", my_pid, NULL);
	lockpath = t_strconcat(index->dir, "/" DIRLOCK_FILE_PREFIX, NULL);

	if (lock_type == MAIL_LOCK_UNLOCK)
		return mail_index_unlock_dir(index, private_path, lockpath);

	(void)unlink(private_path);
	fd = open(private_path, O_RDWR | O_CREAT | O_EXCL, 0660);
	if (fd == -1) {
		if (errno == ENOSPC)
			index->nodiskspace = TRUE;
		index_file_set_syscall_error(index, private_path, "open()");
		return FALSE;
	}

	/* try to link the file into lock file. */
	first = TRUE; max_wait_time = time(NULL) + MAX_LOCK_WAIT_SECONDS;
	while (link(private_path, lockpath) < 0) {
		if (errno == ENOSPC)
			index->nodiskspace = TRUE;

		if (errno != EEXIST) {
			orig_errno = errno;

			/* NFS may die and link() fail even if it really
			   was created */
			if (stat(private_path, &st) == 0 && st.st_nlink == 2)
				break;

			errno = orig_errno;
			index_set_error(index, "link(%s, %s) lock failed: %m",
					private_path, lockpath);
			return FALSE;
		}

		if (first) {
			/* cleanup lock files once */
			first = FALSE;
			if (mail_index_cleanup_dir_locks(index->dir))
				continue; /* lock was deleted, try again */
		}

		if (time(NULL) > max_wait_time) {
			index_set_error(index, "Timeout waiting lock in "
					"directory %s", index->dir);
			return FALSE;
		}

		usleep(LOCK_RANDOM_USLEEP_TIME);
	}

	return TRUE;
}
