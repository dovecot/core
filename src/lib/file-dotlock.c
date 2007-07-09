/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "randgen.h"
#include "write-full.h"
#include "safe-mkstemp.h"
#include "file-dotlock.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <utime.h>
#include <sys/stat.h>

#define DEFAULT_LOCK_SUFFIX ".lock"

/* 0.1 .. 0.2msec */
#define LOCK_RANDOM_USLEEP_TIME (100000 + (unsigned int)rand() % 100000)

/* If the dotlock is newer than this, don't verify that the PID it contains
   is valid (since it most likely is). */
#define STALE_PID_CHECK_SECS 2

/* Maximum difference between current time and create file's ctime before
   logging a warning. Should be less than a second in normal operation. */
#define MAX_TIME_DIFF 30

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

	bool have_pid, use_io_notify;
	time_t last_pid_check;
	time_t last_change;
};

static struct dotlock *
file_dotlock_alloc(const struct dotlock_settings *settings)
{
	struct dotlock *dotlock;

	dotlock = i_new(struct dotlock, 1);
	dotlock->settings = *settings;
	if (dotlock->settings.lock_suffix == NULL)
		dotlock->settings.lock_suffix = DEFAULT_LOCK_SUFFIX;
	dotlock->fd = -1;

	return dotlock;
}

static pid_t read_local_pid(const char *lock_path)
{
	char buf[512], *host;
	int fd;
	ssize_t ret;

	fd = open(lock_path, O_RDONLY);
	if (fd == -1)
		return -1; /* ignore the actual error */

	/* read line */
	ret = read(fd, buf, sizeof(buf)-1);
	(void)close(fd);
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

	if (!is_numeric(buf, '\0'))
		return -1;
	return (pid_t)strtoul(buf, NULL, 0);
}

static bool
update_change_info(const struct stat *st, struct file_change_info *change,
		   time_t *last_change_r, time_t now)
{
	if (change->ino != st->st_ino || !CMP_DEV_T(change->dev, st->st_dev) ||
	    change->ctime != st->st_ctime || change->mtime != st->st_mtime ||
	    change->size != st->st_size) {
		time_t change_time = now;

		if (change->ctime == 0) {
			/* First check, set last_change to file's change time.
			   Use mtime instead if it's higher, but only if it's
			   not higher than current time, because the mtime
			   can also be used for keeping metadata. */
			change_time = st->st_mtime > now ? st->st_ctime :
				I_MAX(st->st_ctime, st->st_mtime);
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

	if (lstat(lock_info->lock_path, &st) < 0) {
		if (errno != ENOENT) {
			i_error("lstat(%s) failed: %m", lock_info->lock_path);
			return -1;
		}
		return 1;
	}

	*changed_r = update_change_info(&st, &lock_info->lock_info,
					&lock_info->last_change, now);
	return 0;
}

static int check_lock(time_t now, struct lock_info *lock_info)
{
	time_t stale_timeout = lock_info->set->stale_timeout;
	pid_t pid;
	bool changed;
	int ret;

	if ((ret = update_lock_info(now, lock_info, &changed)) != 0)
		return ret;
	if (changed) {
		/* either our first check or someone else got the lock file.
		   if the dotlock was created only a couple of seconds ago,
		   don't bother to read its PID. */
		pid = lock_info->lock_info.mtime >=
			now - STALE_PID_CHECK_SECS ? -1 :
			read_local_pid(lock_info->lock_path);
		lock_info->have_pid = pid != -1;
	} else if (!lock_info->have_pid) {
		/* no pid checking */
		pid = -1;
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
			if (pid != getpid())
				return 0;
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
			if (unlink(lock_info->lock_path) < 0 &&
			    errno != ENOENT) {
				i_error("unlink(%s) failed: %m",
					lock_info->lock_path);
				return -1;
			}
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
		if (stat(lock_info->path, &st) < 0) {
			if (errno == ENOENT) {
				/* file doesn't exist. treat it as if
				   it hasn't changed */
			} else {
				i_error("stat(%s) failed: %m", lock_info->path);
				return -1;
			}
		} else {
			(void)update_change_info(&st, &lock_info->file_info,
						 &lock_info->last_change, now);
		}
	}

	if (now > lock_info->last_change + stale_timeout) {
		/* no changes for a while, assume stale lock */
		if (unlink(lock_info->lock_path) < 0 && errno != ENOENT) {
			i_error("unlink(%s) failed: %m", lock_info->lock_path);
			return -1;
		}
		return 1;
	}

	return 0;
}

static int file_write_pid(int fd, const char *path)
{
	const char *str;

	/* write our pid and host, if possible */
	str = t_strdup_printf("%s:%s", my_pid, my_hostname);
	if (write_full(fd, str, strlen(str)) < 0) {
		/* failed, leave it empty then */
		if (ftruncate(fd, 0) < 0) {
			i_error("ftruncate(%s) failed: %m", path);
			return -1;
		}
	}
	return 0;
}

static int try_create_lock_hardlink(struct lock_info *lock_info, bool write_pid,
				    string_t *tmp_path)
{
	const char *temp_prefix = lock_info->set->temp_prefix;
	const char *p;

	if (lock_info->temp_path == NULL) {
		/* we'll need our temp file first. */
		i_assert(lock_info->fd == -1);

		p = strrchr(lock_info->lock_path, '/');

		str_truncate(tmp_path, 0);
		if (temp_prefix != NULL) {
			if (*temp_prefix != '/' && p != NULL) {
				/* add directory */
				str_append_n(tmp_path, lock_info->lock_path,
					     p - lock_info->lock_path);
				str_append_c(tmp_path, '/');
			}
			str_append(tmp_path, temp_prefix);
		} else {
			if (p != NULL) {
				/* add directory */
				str_append_n(tmp_path, lock_info->lock_path,
					     p - lock_info->lock_path);
				str_append_c(tmp_path, '/');
			}
			str_printfa(tmp_path, ".temp.%s.%s.",
				    my_hostname, my_pid);
		}

		lock_info->fd = safe_mkstemp(tmp_path, 0666,
					     (uid_t)-1, (gid_t)-1);
		if (lock_info->fd == -1)
			return -1;

		if (write_pid) {
			if (file_write_pid(lock_info->fd,
					   str_c(tmp_path)) < 0) {
				(void)close(lock_info->fd);
				lock_info->fd = -1;
				return -1;
			}
		}

                lock_info->temp_path = str_c(tmp_path);
	}

	if (link(lock_info->temp_path, lock_info->lock_path) < 0) {
		if (errno == EEXIST)
			return 0;

		i_error("link(%s, %s) failed: %m",
			lock_info->temp_path, lock_info->lock_path);
		return -1;
	}

	if (unlink(lock_info->temp_path) < 0) {
		i_error("unlink(%s) failed: %m", lock_info->temp_path);
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

		i_error("open(%s) failed: %m", lock_info->lock_path);
		return -1;
	}

	if (write_pid) {
		if (file_write_pid(fd, lock_info->lock_path) < 0) {
			(void)close(fd);
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
		usleep(LOCK_RANDOM_USLEEP_TIME);
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
	case IO_NOTIFY_DISABLED:
		/* listening for files not supported */
		io_loop_destroy(&ioloop);
		lock_info->use_io_notify = FALSE;
		usleep(LOCK_RANDOM_USLEEP_TIME);
		return;
	}
	to = timeout_add(LOCK_RANDOM_USLEEP_TIME/1000,
			 dotlock_wait_end, ioloop);
	io_loop_run(ioloop);
	io_remove(&io);
	timeout_remove(&to);
	io_loop_destroy(&ioloop);
}

static int dotlock_create(const char *path, struct dotlock *dotlock,
			  enum dotlock_create_flags flags, bool write_pid)
{
	const struct dotlock_settings *set = &dotlock->settings;
	const char *lock_path;
	struct lock_info lock_info;
	struct stat st;
	unsigned int stale_notify_threshold;
	unsigned int change_secs, wait_left;
	time_t now, max_wait_time, last_notify;
	string_t *tmp_path;
	int ret;
	bool do_wait;

	now = time(NULL);

	lock_path = t_strconcat(path, set->lock_suffix, NULL);
	stale_notify_threshold = set->stale_timeout / 2;
	max_wait_time = (flags & DOTLOCK_CREATE_FLAG_NONBLOCK) != 0 ? 0 :
		now + set->timeout;
	tmp_path = t_str_new(256);

	memset(&lock_info, 0, sizeof(lock_info));
	lock_info.path = path;
	lock_info.set = set;
	lock_info.lock_path = lock_path;
	lock_info.fd = -1;
	lock_info.use_io_notify = set->use_io_notify;
;
	last_notify = 0; do_wait = FALSE;

	do {
		if (do_wait) {
			dotlock_wait(&lock_info);
			do_wait = FALSE;
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
							 tmp_path);
			if (ret != 0)
				break;
		}

		do_wait = TRUE;
		if (last_notify != now && set->callback != NULL) {
			last_notify = now;
			change_secs = now - lock_info.last_change;
			wait_left = max_wait_time - now;

			t_push();
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
			} else {
				(void)set->callback(wait_left, FALSE,
						    set->context);
			}
			t_pop();
		}

		now = time(NULL);
	} while (now < max_wait_time);

	if (ret > 0) {
		if (fstat(lock_info.fd, &st) < 0) {
			i_error("fstat(%s) failed: %m", lock_path);
			ret = -1;
		} else {
			/* successful dotlock creation */
			dotlock->dev = st.st_dev;
			dotlock->ino = st.st_ino;

			dotlock->path = i_strdup(path);
			dotlock->fd = lock_info.fd;
                        dotlock->lock_time = now;
			lock_info.fd = -1;

			if (st.st_ctime + MAX_TIME_DIFF < now ||
			    st.st_ctime - MAX_TIME_DIFF > now) {
				i_warning("Created dotlock file's timestamp is "
					  "different than current time "
					  "(%s vs %s): %s", dec2str(st.st_ctime),
					  dec2str(now), path);
			}
		}
	}

	if (lock_info.fd != -1) {
		int old_errno = errno;

		if (close(lock_info.fd) < 0)
			i_error("close(%s) failed: %m", lock_path);
		errno = old_errno;
	}
	if (lock_info.temp_path != NULL) {
		if (unlink(lock_info.temp_path) < 0)
			i_error("unlink(%s) failed: %m", lock_info.temp_path);
	}

	if (ret == 0)
		errno = EAGAIN;
	return ret;
}

static void file_dotlock_free(struct dotlock *dotlock)
{
	int old_errno;

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

int file_dotlock_create(const struct dotlock_settings *set, const char *path,
			enum dotlock_create_flags flags,
			struct dotlock **dotlock_r)
{
	struct dotlock *dotlock;
	const char *lock_path;
	struct stat st;
	int fd, ret;

	*dotlock_r = NULL;

	t_push();
	dotlock = file_dotlock_alloc(set);
	lock_path = t_strconcat(path, dotlock->settings.lock_suffix, NULL);

	ret = dotlock_create(path, dotlock, flags, TRUE);
	if (ret <= 0 || (flags & DOTLOCK_CREATE_FLAG_CHECKONLY) != 0) {
		file_dotlock_free(dotlock);
		t_pop();
		return ret;
	}

	fd = dotlock->fd;
	dotlock->fd = -1;

	if (close(fd) < 0) {
		i_error("close(%s) failed: %m", lock_path);
		file_dotlock_free(dotlock);
		t_pop();
		return -1;
	}

	/* some NFS implementations may have used cached mtime in previous
	   fstat() call. Check again to avoid "dotlock was modified" errors. */
	if (stat(lock_path, &st) < 0) {
		if (errno != ENOENT)
			i_error("stat(%s) failed: %m", lock_path);
		else {
			i_error("dotlock %s was immediately deleted under us",
				lock_path);
		}
                file_dotlock_free(dotlock);
		t_pop();
		return -1;
	}
	/* extra sanity check won't hurt.. */
	if (st.st_dev != dotlock->dev || st.st_ino != dotlock->ino) {
		i_error("dotlock %s was immediately recreated under us",
			lock_path);
                file_dotlock_free(dotlock);
		t_pop();
		return -1;
	}
	dotlock->mtime = st.st_mtime;

	*dotlock_r = dotlock;
	t_pop();
	return 1;
}

int file_dotlock_delete(struct dotlock **dotlock_p)
{
	struct dotlock *dotlock;
	const char *lock_path;
        struct stat st;

	dotlock = *dotlock_p;
	*dotlock_p = NULL;

	lock_path = file_dotlock_get_lock_path(dotlock);
	if (lstat(lock_path, &st) < 0) {
		if (errno == ENOENT) {
			i_warning("Our dotlock file %s was deleted "
				  "(kept it %d secs)", lock_path,
				  (int)(time(NULL) - dotlock->lock_time));
			file_dotlock_free(dotlock);
			return 0;
		}

		i_error("lstat(%s) failed: %m", lock_path);
		file_dotlock_free(dotlock);
		return -1;
	}

	if (dotlock->ino != st.st_ino ||
	    !CMP_DEV_T(dotlock->dev, st.st_dev)) {
		i_warning("Our dotlock file %s was overridden "
			  "(kept it %d secs)", lock_path,
			  (int)(dotlock->lock_time - time(NULL)));
		errno = EEXIST;
		file_dotlock_free(dotlock);
		return 0;
	}

	if (dotlock->mtime != st.st_mtime && dotlock->fd == -1) {
		i_warning("Our dotlock file %s was modified (%s vs %s), "
			  "assuming it wasn't overridden (kept it %d secs)",
			  lock_path,
			  dec2str(dotlock->mtime), dec2str(st.st_mtime),
			  (int)(time(NULL) - dotlock->lock_time));
	}

	if (unlink(lock_path) < 0) {
		if (errno == ENOENT) {
			i_warning("Our dotlock file %s was deleted "
				  "(kept it %d secs)", lock_path,
				  (int)(time(NULL) - dotlock->lock_time));
			file_dotlock_free(dotlock);
			return 0;
		}

		i_error("unlink(%s) failed: %m", lock_path);
		file_dotlock_free(dotlock);
		return -1;
	}

	file_dotlock_free(dotlock);
	return 1;
}

int file_dotlock_open(const struct dotlock_settings *set, const char *path,
		      enum dotlock_create_flags flags,
		      struct dotlock **dotlock_r)
{
	struct dotlock *dotlock;
	int ret;

	dotlock = file_dotlock_alloc(set);

	t_push();
	ret = dotlock_create(path, dotlock, flags, FALSE);
	t_pop();

	if (ret <= 0) {
		file_dotlock_free(dotlock);
		*dotlock_r = NULL;
		return -1;
	}

	*dotlock_r = dotlock;
	return dotlock->fd;
}

int file_dotlock_replace(struct dotlock **dotlock_p,
			 enum dotlock_replace_flags flags)
{
	struct dotlock *dotlock;
	struct stat st, st2;
	const char *lock_path;
	int fd;

	dotlock = *dotlock_p;
	*dotlock_p = NULL;

	fd = dotlock->fd;
	if ((flags & DOTLOCK_REPLACE_FLAG_DONT_CLOSE_FD) != 0)
		dotlock->fd = -1;

	lock_path = file_dotlock_get_lock_path(dotlock);
	if ((flags & DOTLOCK_REPLACE_FLAG_VERIFY_OWNER) != 0) {
		if (fstat(fd, &st) < 0) {
			i_error("fstat(%s) failed: %m", lock_path);
			file_dotlock_free(dotlock);
			return -1;
		}

		if (lstat(lock_path, &st2) < 0) {
			i_error("lstat(%s) failed: %m", lock_path);
			file_dotlock_free(dotlock);
			return -1;
		}

		if (st.st_ino != st2.st_ino ||
		    !CMP_DEV_T(st.st_dev, st2.st_dev)) {
			i_warning("Our dotlock file %s was overridden "
				  "(kept it %d secs)", lock_path,
				  (int)(time(NULL) - dotlock->lock_time));
			errno = EEXIST;
			file_dotlock_free(dotlock);
			return 0;
		}
	}

	if (rename(lock_path, dotlock->path) < 0) {
		i_error("rename(%s, %s) failed: %m", lock_path, dotlock->path);
		file_dotlock_free(dotlock);
		return -1;
	}
	file_dotlock_free(dotlock);
	return 1;
}

int file_dotlock_touch(struct dotlock *dotlock)
{
	time_t now = time(NULL);
	struct utimbuf buf;
	const char *lock_path;
	int ret = 0;

	if (dotlock->mtime == now)
		return 0;

	dotlock->mtime = now;
	buf.actime = buf.modtime = now;

	t_push();
	lock_path = file_dotlock_get_lock_path(dotlock);
	if (utime(lock_path, &buf) < 0) {
		i_error("utime(%s) failed: %m", lock_path);
		ret = -1;
	}
	t_pop();
	return ret;
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
