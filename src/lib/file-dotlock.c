/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "file-lock.h"
#include "eacces-error.h"
#include "write-full.h"
#include "safe-mkstemp.h"
#include "nfs-workarounds.h"
#include "file-dotlock.h"
#include "sleep.h"

#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <utime.h>
#include <sys/stat.h>

#define DEFAULT_LOCK_SUFFIX ".lock"

/* 0.1 .. 0.2msec */
#define LOCK_RANDOM_USLEEP_TIME (100000 + (unsigned int)i_rand() % 100000)
/* Maximum 3 second wait between dotlock checks */
#define LOCK_MAX_WAIT_USECS (1000000 * 3)

/* If the dotlock is newer than this, don't verify that the PID it contains
   is valid (since it most likely is). */
#define STALE_PID_CHECK_SECS 2

/* Maximum difference between current time and create file's ctime before
   logging a warning. Should be less than a second in normal operation. */
#define MAX_TIME_DIFF 30
/* NFS may return a cached mtime in stat(). A later non-cached stat() may
   return a slightly different mtime. Allow the difference to be this much
   and still consider it to be the same mtime. */
#define FILE_DOTLOCK_MAX_STAT_MTIME_DIFF 1

struct dotlock {
	struct dotlock_settings settings;

	dev_t dev;
	ino_t ino;
	time_t mtime;

	char *path;
	char *lock_path;
	int fd;

	time_t lock_time;
};

struct file_change_info {
	dev_t dev;
	ino_t ino;
	off_t size;
	time_t ctime, mtime;
};

struct lock_info {
	const struct dotlock_settings *set;
	const char *path, *lock_path, *temp_path;
	int fd;

	struct file_change_info lock_info;
	struct file_change_info file_info;

	time_t last_pid_check;
	time_t last_change;
	unsigned int wait_usecs;

	bool have_pid:1;
	bool pid_read:1;
	bool use_io_notify:1;
	bool lock_stated:1;
};

static struct dotlock *
file_dotlock_alloc(const struct dotlock_settings *settings, const char *path)
{
	struct dotlock *dotlock;

	dotlock = i_new(struct dotlock, 1);
	dotlock->settings = *settings;
	if (dotlock->settings.lock_suffix == NULL)
		dotlock->settings.lock_suffix = DEFAULT_LOCK_SUFFIX;
	dotlock->path = i_strdup(path);
	dotlock->fd = -1;

	return dotlock;
}

static pid_t read_local_pid(const char *lock_path)
{
	char buf[512], *host;
	int fd;
	ssize_t ret;
	pid_t pid;

	fd = open(lock_path, O_RDONLY);
	if (fd == -1)
		return -1; /* ignore the actual error */

	/* read line */
	ret = read(fd, buf, sizeof(buf)-1);
	i_close_fd(&fd);
	if (ret <= 0)
		return -1;

	/* fix the string */
	if (buf[ret-1] == '\n')
		ret--;
	buf[ret] = '\0';

	/* it should contain pid:host */
	host = strchr(buf, ':');
	if (host == NULL)
		return -1;
	*host++ = '\0';

	/* host must be ours */
	if (strcmp(host, my_hostname) != 0)
		return -1;

	if (str_to_pid(buf, &pid) < 0)
		return -1;
	if (pid <= 0)
		return -1;
	return pid;
}

static bool
update_change_info(const struct stat *st, struct file_change_info *change,
		   time_t *last_change_r, time_t now, bool check_ctime)
{
	/* ctime is checked only if we're not doing NFS attribute cache
	   flushes. it changes them. */
	if (change->ino != st->st_ino || !CMP_DEV_T(change->dev, st->st_dev) ||
	    (change->ctime != st->st_ctime && check_ctime) ||
	    change->mtime != st->st_mtime || change->size != st->st_size) {
		time_t change_time = now;

		if (change->ctime == 0) {
			/* First check, set last_change to file's change time.
			   Use mtime instead if it's higher, but only if it's
			   not higher than current time, because the mtime
			   can also be used for keeping metadata. */
			change_time = st->st_mtime <= now &&
				(st->st_mtime > st->st_ctime || !check_ctime) ?
				st->st_mtime : st->st_ctime;
		}
		if (*last_change_r < change_time)
			*last_change_r = change_time;
		change->ino = st->st_ino;
		change->dev = st->st_dev;
		change->ctime = st->st_ctime;
		change->mtime = st->st_mtime;
		change->size = st->st_size;
		return TRUE;
	}
	return FALSE;
}

static int update_lock_info(time_t now, struct lock_info *lock_info,
			    bool *changed_r)
{
	struct stat st;

	/* don't waste time flushing attribute cache the first time we're here.
	   if it's stale we'll get back here soon. */
	if (lock_info->set->nfs_flush && lock_info->lock_stated) {
		nfs_flush_file_handle_cache(lock_info->lock_path);
		nfs_flush_attr_cache_unlocked(lock_info->lock_path);
	}

	lock_info->lock_stated = TRUE;
	if (nfs_safe_lstat(lock_info->lock_path, &st) < 0) {
		if (errno != ENOENT) {
			i_error("lstat(%s) failed: %m", lock_info->lock_path);
			return -1;
		}
		return 1;
	}

	*changed_r = update_change_info(&st, &lock_info->lock_info,
					&lock_info->last_change, now,
					!lock_info->set->nfs_flush);
	return 0;
}

static int dotlock_override(struct lock_info *lock_info)
{
	if (i_unlink_if_exists(lock_info->lock_path) < 0)
		return -1;

	/* make sure we sleep for a while after overriding the lock file.
	   otherwise another process might try to override it at the same time
	   and unlink our newly created dotlock. */
	if (lock_info->use_io_notify)
		i_sleep_usecs(LOCK_RANDOM_USLEEP_TIME);
	return 0;
}

static int check_lock(time_t now, struct lock_info *lock_info)
{
	time_t stale_timeout = lock_info->set->stale_timeout;
	pid_t pid = -1;
	bool changed;
	int ret;

	if ((ret = update_lock_info(now, lock_info, &changed)) != 0)
		return ret;
	if (changed || !lock_info->pid_read) {
		/* either our first check or someone else got the lock file.
		   if the dotlock was created only a couple of seconds ago,
		   don't bother to read its PID. */
		if (lock_info->lock_info.mtime >= now - STALE_PID_CHECK_SECS)
			lock_info->pid_read = FALSE;
		else {
			pid = read_local_pid(lock_info->lock_path);
			lock_info->pid_read = TRUE;
		}
		lock_info->have_pid = pid != -1;
	} else if (!lock_info->have_pid) {
		/* no pid checking */
	} else {
		if (lock_info->last_pid_check == now) {
			/* we just checked the pid */
			return 0;
		}

		/* re-read the pid. even if all times and inodes are the same,
		   the PID in the file might have changed if lock files were
		   rapidly being recreated. */
		pid = read_local_pid(lock_info->lock_path);
		lock_info->have_pid = pid != -1;
	}

	if (lock_info->have_pid) {
		/* we've local PID. Check if it exists. */
		if (kill(pid, 0) == 0 || errno != ESRCH) {
			if (pid != getpid()) {
				/* process exists, don't override */
				return 0;
			}
			/* it's us. either we're locking it again, or it's a
			   stale lock file with same pid than us. either way,
			   recreate it.. */
		}

		/* doesn't exist - now check again if the dotlock was just
		   deleted or replaced */
		if ((ret = update_lock_info(now, lock_info, &changed)) != 0)
			return ret;

		if (!changed) {
			/* still there, go ahead and override it */
			return dotlock_override(lock_info);
		}
		return 1;
	}

	if (stale_timeout == 0) {
		/* no change checking */
		return 0;
	}

	if (now > lock_info->last_change + stale_timeout) {
		struct stat st;

		/* possibly stale lock file. check also the timestamp of the
		   file we're protecting. */
		if (lock_info->set->nfs_flush) {
			nfs_flush_file_handle_cache(lock_info->path);
			nfs_flush_attr_cache_maybe_locked(lock_info->path);
		}
		if (nfs_safe_stat(lock_info->path, &st) < 0) {
			if (errno == ENOENT) {
				/* file doesn't exist. treat it as if
				   it hasn't changed */
			} else {
				i_error("stat(%s) failed: %m", lock_info->path);
				return -1;
			}
		} else {
			(void)update_change_info(&st, &lock_info->file_info,
						 &lock_info->last_change, now,
						 !lock_info->set->nfs_flush);
		}
	}

	if (now > lock_info->last_change + stale_timeout) {
		/* no changes for a while, assume stale lock */
		return dotlock_override(lock_info);
	}

	return 0;
}

static int file_write_pid(int fd, const char *path, bool nfs_flush)
{
	const char *str;

	/* write our pid and host, if possible */
	str = t_strdup_printf("%s:%s", my_pid, my_hostname);
	if (write_full(fd, str, strlen(str)) < 0 ||
	    (nfs_flush && fdatasync(fd) < 0)) {
		/* failed, leave it empty then */
		if (ftruncate(fd, 0) < 0) {
			i_error("ftruncate(%s) failed: %m", path);
			return -1;
		}
	}
	return 0;
}

static int try_create_lock_hardlink(struct lock_info *lock_info, bool write_pid,
				    string_t *tmp_path, time_t now)
{
	const char *temp_prefix = lock_info->set->temp_prefix;
	const char *p;
	mode_t old_mask;
	struct stat st;

	if (lock_info->temp_path == NULL) {
		/* we'll need our temp file first. */
		i_assert(lock_info->fd == -1);

		p = strrchr(lock_info->lock_path, '/');

		str_truncate(tmp_path, 0);
		if (temp_prefix != NULL) {
			if (*temp_prefix != '/' && p != NULL) {
				/* add directory */
				str_append_data(tmp_path, lock_info->lock_path,
						p - lock_info->lock_path);
				str_append_c(tmp_path, '/');
			}
			str_append(tmp_path, temp_prefix);
		} else {
			if (p != NULL) {
				/* add directory */
				str_append_data(tmp_path, lock_info->lock_path,
						p - lock_info->lock_path);
				str_append_c(tmp_path, '/');
			}
			str_printfa(tmp_path, ".temp.%s.%s.",
				    my_hostname, my_pid);
		}

		old_mask = umask(0666);
		lock_info->fd = safe_mkstemp(tmp_path, 0666 ^ old_mask,
					     (uid_t)-1, (gid_t)-1);
		umask(old_mask);
		if (lock_info->fd == -1)
			return -1;

		if (write_pid) {
			if (file_write_pid(lock_info->fd,
					   str_c(tmp_path),
					   lock_info->set->nfs_flush) < 0) {
				i_close_fd(&lock_info->fd);
				return -1;
			}
		}

                lock_info->temp_path = str_c(tmp_path);
	} else if (fstat(lock_info->fd, &st) < 0) {
		i_error("fstat(%s) failed: %m", lock_info->temp_path);
		return -1;
	} else if (st.st_ctime < now) {
		/* we've been waiting for a while.
		   refresh the file's timestamp. */
		if (utime(lock_info->temp_path, NULL) < 0)
			i_error("utime(%s) failed: %m", lock_info->temp_path);
	}

	if (nfs_safe_link(lock_info->temp_path,
			  lock_info->lock_path, TRUE) < 0) {
		if (errno == EEXIST)
			return 0;

		if (errno != EACCES) {
			i_error("link(%s, %s) failed: %m",
				lock_info->temp_path, lock_info->lock_path);
		}
		return -1;
	}

	if (i_unlink(lock_info->temp_path) < 0) {
		/* non-fatal, continue */
	}
	lock_info->temp_path = NULL;
	return 1;
}

static int try_create_lock_excl(struct lock_info *lock_info, bool write_pid)
{
	int fd;

	fd = open(lock_info->lock_path, O_RDWR | O_EXCL | O_CREAT, 0666);
	if (fd == -1) {
		if (errno == EEXIST)
			return 0;

		if (errno != ENOENT && errno != EACCES)
			i_error("open(%s) failed: %m", lock_info->lock_path);
		return -1;
	}

	if (write_pid) {
		if (file_write_pid(fd, lock_info->lock_path,
				   lock_info->set->nfs_flush) < 0) {
			i_close_fd(&fd);
			return -1;
		}
	}

	lock_info->fd = fd;
	return 1;
}

static void dotlock_wait_end(struct ioloop *ioloop)
{
	io_loop_stop(ioloop);
}

static void dotlock_wait(struct lock_info *lock_info)
{
	struct ioloop *ioloop;
	struct io *io;
	struct timeout *to;

	if (!lock_info->use_io_notify) {
		i_sleep_usecs(lock_info->wait_usecs);
		return;
	}

	ioloop = io_loop_create();
	switch (io_add_notify(lock_info->lock_path, dotlock_wait_end,
			      ioloop, &io)) {
	case IO_NOTIFY_ADDED:
		break;
	case IO_NOTIFY_NOTFOUND:
		/* the lock file doesn't exist anymore, don't sleep */
		io_loop_destroy(&ioloop);
		return;
	case IO_NOTIFY_NOSUPPORT:
		/* listening for files not supported */
		io_loop_destroy(&ioloop);
		lock_info->use_io_notify = FALSE;
		i_sleep_usecs(LOCK_RANDOM_USLEEP_TIME);
		return;
	}
	/* timeout after a random time even when using notify, since it
	   doesn't work reliably with e.g. NFS. */
	to = timeout_add(lock_info->wait_usecs/1000,
			 dotlock_wait_end, ioloop);
	io_loop_run(ioloop);
	io_remove(&io);
	timeout_remove(&to);
	io_loop_destroy(&ioloop);
}

static int
dotlock_create(struct dotlock *dotlock, enum dotlock_create_flags flags,
	       bool write_pid, const char **lock_path_r)
{
	const struct dotlock_settings *set = &dotlock->settings;
	const char *lock_path;
	struct lock_info lock_info;
	struct stat st;
	unsigned int stale_notify_threshold;
	unsigned int change_secs, wait_left;
	time_t now, max_wait_time, last_notify;
	time_t prev_last_change = 0, prev_wait_update = 0;
	string_t *tmp_path;
	int ret;
	bool do_wait;

	now = time(NULL);

	lock_path = *lock_path_r =
		t_strconcat(dotlock->path, set->lock_suffix, NULL);
	stale_notify_threshold = set->stale_timeout / 2;
	max_wait_time = (flags & DOTLOCK_CREATE_FLAG_NONBLOCK) != 0 ? 0 :
		now + set->timeout;
	tmp_path = t_str_new(256);

	i_zero(&lock_info);
	lock_info.path = dotlock->path;
	lock_info.set = set;
	lock_info.lock_path = lock_path;
	lock_info.fd = -1;
	lock_info.use_io_notify = set->use_io_notify;

	last_notify = 0; do_wait = FALSE;

	file_lock_wait_start();
	do {
		if (do_wait) {
			if (prev_last_change != lock_info.last_change) {
				/* dotlock changed since last check,
				   reset the wait time */
				lock_info.wait_usecs = LOCK_RANDOM_USLEEP_TIME;
				prev_last_change = lock_info.last_change;
				prev_wait_update = now;
			} else if (prev_wait_update != now &&
				   lock_info.wait_usecs < LOCK_MAX_WAIT_USECS) {
				/* we've been waiting for a while now, increase
				   the wait time to avoid wasting CPU */
				prev_wait_update = now;
				lock_info.wait_usecs += lock_info.wait_usecs/2;
			}
			dotlock_wait(&lock_info);
			now = time(NULL);
		}

		ret = check_lock(now, &lock_info);
		if (ret < 0)
			break;

		if (ret == 1) {
			if ((flags & DOTLOCK_CREATE_FLAG_CHECKONLY) != 0)
				break;

			ret = set->use_excl_lock ?
				try_create_lock_excl(&lock_info, write_pid) :
				try_create_lock_hardlink(&lock_info, write_pid,
							 tmp_path, now);
			if (ret != 0) {
				/* if we succeeded, get the current time once
				   more in case disk I/O usage was really high
				   and it took a long time to create the lock */
				now = time(NULL);
				break;
			}
		}

		if (last_notify != now && set->callback != NULL) {
			last_notify = now;
			change_secs = now - lock_info.last_change;
			wait_left = max_wait_time - now;

			if (change_secs >= stale_notify_threshold &&
			    change_secs <= wait_left) {
				unsigned int secs_left =
					set->stale_timeout < change_secs ?
					0 : set->stale_timeout - change_secs;
				if (!set->callback(secs_left, TRUE,
						   set->context)) {
					/* we don't want to override */
					lock_info.last_change = now;
				}
			} else if (wait_left > 0) {
				(void)set->callback(wait_left, FALSE,
						    set->context);
			}
		}

		do_wait = TRUE;
		now = time(NULL);
	} while (now < max_wait_time);
	file_lock_wait_end(dotlock->path);

	if (ret > 0) {
		i_assert(lock_info.fd != -1);
		if (fstat(lock_info.fd, &st) < 0) {
			i_error("fstat(%s) failed: %m", lock_path);
			ret = -1;
		} else {
			/* successful dotlock creation */
			dotlock->dev = st.st_dev;
			dotlock->ino = st.st_ino;

			dotlock->fd = lock_info.fd;
                        dotlock->lock_time = now;
			lock_info.fd = -1;

			if (st.st_ctime + MAX_TIME_DIFF < now ||
			    st.st_ctime - MAX_TIME_DIFF > now) {
				i_warning("Created dotlock file's timestamp is "
					  "different than current time "
					  "(%s vs %s): %s", dec2str(st.st_ctime),
					  dec2str(now), dotlock->path);
			}
		}
	}

	if (lock_info.fd != -1) {
		int old_errno = errno;

		if (close(lock_info.fd) < 0)
			i_error("close(%s) failed: %m", lock_path);
		errno = old_errno;
	}
	if (lock_info.temp_path != NULL)
		i_unlink(lock_info.temp_path);

	if (ret == 0)
		errno = EAGAIN;
	return ret;
}

static void file_dotlock_free(struct dotlock **_dotlock)
{
	struct dotlock *dotlock = *_dotlock;
	int old_errno;

	*_dotlock = NULL;

	if (dotlock->fd != -1) {
		old_errno = errno;
		if (close(dotlock->fd) < 0)
			i_error("close(%s) failed: %m", dotlock->path);
		dotlock->fd = -1;
		errno = old_errno;
	}

	i_free(dotlock->path);
	i_free(dotlock->lock_path);
	i_free(dotlock);
}

static int file_dotlock_create_real(struct dotlock *dotlock,
				    enum dotlock_create_flags flags)
{
	const char *lock_path;
	struct stat st;
	int fd, ret;

	ret = dotlock_create(dotlock, flags, TRUE, &lock_path);
	if (ret <= 0 || (flags & DOTLOCK_CREATE_FLAG_CHECKONLY) != 0)
		return ret;

	fd = dotlock->fd;
	dotlock->fd = -1;

	if (close(fd) < 0) {
		i_error("close(%s) failed: %m", lock_path);
		return -1;
	}

	/* With NFS the writes may have been flushed only when closing the
	   file. Get the mtime again after that to avoid "dotlock was modified"
	   errors. */
	if (lstat(lock_path, &st) < 0) {
		if (errno != ENOENT)
			i_error("stat(%s) failed: %m", lock_path);
		else {
			i_error("dotlock %s was immediately deleted under us",
				lock_path);
		}
		return -1;
	}
	/* extra sanity check won't hurt.. */
	if (st.st_dev != dotlock->dev || st.st_ino != dotlock->ino) {
		errno = ENOENT;
		i_error("dotlock %s was immediately recreated under us",
			lock_path);
		return -1;
	}
	dotlock->mtime = st.st_mtime;
	return 1;
}

int file_dotlock_create(const struct dotlock_settings *set, const char *path,
			enum dotlock_create_flags flags,
			struct dotlock **dotlock_r)
{
	struct dotlock *dotlock;
	int ret;

	dotlock = file_dotlock_alloc(set, path);
	T_BEGIN {
		ret = file_dotlock_create_real(dotlock, flags);
	} T_END;
	if (ret <= 0 || (flags & DOTLOCK_CREATE_FLAG_CHECKONLY) != 0)
		file_dotlock_free(&dotlock);

	*dotlock_r = dotlock;
	return ret;
}

static void dotlock_replaced_warning(struct dotlock *dotlock, bool deleted)
{
	const char *lock_path;
	time_t now = time(NULL);

	lock_path = file_dotlock_get_lock_path(dotlock);
	if (dotlock->mtime == dotlock->lock_time) {
		i_warning("Our dotlock file %s was %s "
			  "(locked %d secs ago, touched %d secs ago)",
			  lock_path, deleted ? "deleted" : "overridden",
			  (int)(now - dotlock->lock_time),
			  (int)(now - dotlock->mtime));
	} else {
		i_warning("Our dotlock file %s was %s "
			  "(kept it %d secs)", lock_path,
			  deleted ? "deleted" : "overridden",
			  (int)(now - dotlock->lock_time));
	}
}

static bool file_dotlock_has_mtime_changed(time_t t1, time_t t2)
{
	time_t diff;

	if (t1 == t2)
		return FALSE;

	/* with NFS t1 may have been looked up from local cache.
	   allow it to be a little bit different. */
	diff = t1 > t2 ? t1-t2 : t2-t1;
	return diff > FILE_DOTLOCK_MAX_STAT_MTIME_DIFF;
}

int file_dotlock_delete(struct dotlock **dotlock_p)
{
	struct dotlock *dotlock;
	const char *lock_path;
        struct stat st;
	int ret;

	dotlock = *dotlock_p;
	*dotlock_p = NULL;

	lock_path = file_dotlock_get_lock_path(dotlock);
	if (nfs_safe_lstat(lock_path, &st) < 0) {
		if (errno == ENOENT) {
			dotlock_replaced_warning(dotlock, TRUE);
			file_dotlock_free(&dotlock);
			return 0;
		}

		i_error("lstat(%s) failed: %m", lock_path);
		file_dotlock_free(&dotlock);
		return -1;
	}

	if (dotlock->ino != st.st_ino ||
	    !CMP_DEV_T(dotlock->dev, st.st_dev)) {
		dotlock_replaced_warning(dotlock, FALSE);
		errno = EEXIST;
		file_dotlock_free(&dotlock);
		return 0;
	}

	if (file_dotlock_has_mtime_changed(dotlock->mtime, st.st_mtime) &&
	    dotlock->fd == -1) {
		i_warning("Our dotlock file %s was modified (%s vs %s), "
			  "assuming it wasn't overridden (kept it %d secs)",
			  lock_path,
			  dec2str(dotlock->mtime), dec2str(st.st_mtime),
			  (int)(time(NULL) - dotlock->lock_time));
	}

	if ((ret = i_unlink_if_exists(lock_path)) == 0)
		dotlock_replaced_warning(dotlock, TRUE);
	file_dotlock_free(&dotlock);
	return ret;
}

int file_dotlock_open(const struct dotlock_settings *set, const char *path,
		      enum dotlock_create_flags flags,
		      struct dotlock **dotlock_r)
{
	struct dotlock *dotlock;
	int ret;

	dotlock = file_dotlock_alloc(set, path);
	T_BEGIN {
		const char *lock_path;

		ret = dotlock_create(dotlock, flags, FALSE, &lock_path);
	} T_END;

	if (ret <= 0) {
		file_dotlock_free(&dotlock);
		*dotlock_r = NULL;
		return -1;
	}

	*dotlock_r = dotlock;
	return dotlock->fd;
}

static int ATTR_NULL(7)
file_dotlock_open_mode_full(const struct dotlock_settings *set, const char *path,
			    enum dotlock_create_flags flags,
			    mode_t mode, uid_t uid, gid_t gid,
			    const char *gid_origin, struct dotlock **dotlock_r)
{
	struct dotlock *dotlock;
	mode_t old_mask;
	int fd;

	old_mask = umask(0666 ^ mode);
	fd = file_dotlock_open(set, path, flags, &dotlock);
	umask(old_mask);

	if (fd != -1 && (uid != (uid_t)-1 || gid != (gid_t)-1)) {
		if (fchown(fd, uid, gid) < 0) {
			if (errno == EPERM && uid == (uid_t)-1) {
				i_error("%s", eperm_error_get_chgrp("fchown",
					file_dotlock_get_lock_path(dotlock),
					gid, gid_origin));
			} else {
				i_error("fchown(%s, %ld, %ld) failed: %m",
					file_dotlock_get_lock_path(dotlock),
					(long)uid, (long)gid);
			}
			file_dotlock_delete(&dotlock);
			return -1;
		}
	}
	*dotlock_r = dotlock;
	return fd;
}

int file_dotlock_open_mode(const struct dotlock_settings *set, const char *path,
			   enum dotlock_create_flags flags,
			   mode_t mode, uid_t uid, gid_t gid,
			   struct dotlock **dotlock_r)
{
	return file_dotlock_open_mode_full(set, path, flags, mode, uid, gid,
					   NULL, dotlock_r);
}

int file_dotlock_open_group(const struct dotlock_settings *set, const char *path,
			    enum dotlock_create_flags flags,
			    mode_t mode, gid_t gid, const char *gid_origin,
			    struct dotlock **dotlock_r)
{
	return file_dotlock_open_mode_full(set, path, flags, mode, (uid_t)-1,
					   gid, gid_origin, dotlock_r);
}

int file_dotlock_replace(struct dotlock **dotlock_p,
			 enum dotlock_replace_flags flags)
{
	struct dotlock *dotlock;
	const char *lock_path;
	bool is_locked;

	dotlock = *dotlock_p;
	*dotlock_p = NULL;

	is_locked = (flags & DOTLOCK_REPLACE_FLAG_VERIFY_OWNER) == 0 ? TRUE :
		file_dotlock_is_locked(dotlock);

	if ((flags & DOTLOCK_REPLACE_FLAG_DONT_CLOSE_FD) != 0)
		dotlock->fd = -1;

	if (!is_locked) {
		dotlock_replaced_warning(dotlock, FALSE);
		errno = EEXIST;
		file_dotlock_free(&dotlock);
		return 0;
	}

	lock_path = file_dotlock_get_lock_path(dotlock);
	if (rename(lock_path, dotlock->path) < 0) {
		i_error("rename(%s, %s) failed: %m", lock_path, dotlock->path);
		if (errno == ENOENT)
			dotlock_replaced_warning(dotlock, TRUE);
		file_dotlock_free(&dotlock);
		return -1;
	}
	file_dotlock_free(&dotlock);
	return 1;
}

int file_dotlock_touch(struct dotlock *dotlock)
{
	time_t now = time(NULL);
	struct utimbuf buf;
	int ret = 0;

	if (dotlock->mtime == now)
		return 0;

	dotlock->mtime = now;
	buf.actime = buf.modtime = now;

	T_BEGIN {
		const char *lock_path = file_dotlock_get_lock_path(dotlock);
		if (utime(lock_path, &buf) < 0) {
			i_error("utime(%s) failed: %m", lock_path);
			ret = -1;
		}
	} T_END;
	return ret;
}

bool file_dotlock_is_locked(struct dotlock *dotlock)
{
	struct stat st, st2;
	const char *lock_path;

	lock_path = file_dotlock_get_lock_path(dotlock);
	if (fstat(dotlock->fd, &st) < 0) {
		i_error("fstat(%s) failed: %m", lock_path);
		return FALSE;
	}

	if (nfs_safe_lstat(lock_path, &st2) < 0) {
		i_error("lstat(%s) failed: %m", lock_path);
		return FALSE;
	}
	return st.st_ino == st2.st_ino && CMP_DEV_T(st.st_dev, st2.st_dev);
}

const char *file_dotlock_get_lock_path(struct dotlock *dotlock)
{
	if (dotlock->lock_path == NULL) {
		dotlock->lock_path =
			i_strconcat(dotlock->path,
				    dotlock->settings.lock_suffix, NULL);
	}
	return dotlock->lock_path;
}
