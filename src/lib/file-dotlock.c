/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "write-full.h"
#include "file-dotlock.h"

#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>

/* 0.1 .. 0.2msec */
#define LOCK_RANDOM_USLEEP_TIME (100000 + (unsigned int)rand() % 100000)

struct lock_info {
	const char *path, *lock_path;
	unsigned int stale_timeout;

	dev_t dev;
	ino_t ino;
	off_t size;
	time_t mtime;

	off_t last_size;
	time_t last_mtime;
	time_t last_change;

	pid_t pid;
	time_t last_pid_check;
};

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

static int check_lock(time_t now, struct lock_info *lock_info)
{
	struct stat st;

	if (lstat(lock_info->lock_path, &st) < 0) {
		if (errno != ENOENT) {
			i_error("lstat(%s) failed: %m", lock_info->lock_path);
			return -1;
		}
		return 1;
	}

	if (lock_info->ino != st.st_ino ||
	    !CMP_DEV_T(lock_info->dev, st.st_dev) ||
	    lock_info->mtime != st.st_mtime ||
	    lock_info->size != st.st_size) {
		/* either our first check or someone else got the lock file.
		   check if it contains a pid whose existence we can verify */
		lock_info->dev = st.st_dev;
		lock_info->ino = st.st_ino;
		lock_info->mtime = st.st_mtime;
		lock_info->size = st.st_size;
		lock_info->pid = read_local_pid(lock_info->lock_path);

		lock_info->last_change = now;
	}

	if (lock_info->pid != -1) {
		/* we've local PID. Check if it exists. */
		if (lock_info->last_pid_check == now)
			return 0;

		if (kill(lock_info->pid, 0) == 0 || errno != ESRCH)
			return 0;

		/* doesn't exist - go ahead and delete */
		if (unlink(lock_info->lock_path) < 0 && errno != ENOENT) {
			i_error("unlink(%s) failed: %m", lock_info->lock_path);
			return -1;
		}
		return 1;
	}

	/* see if the file we're locking is being modified */
	if (stat(lock_info->path, &st) < 0) {
		if (errno == ENOENT) {
			/* file doesn't exist. treat it as if
			   it hasn't changed */
		} else {
			i_error("stat(%s) failed: %m", lock_info->path);
			return -1;
		}
	} else if (lock_info->last_size != st.st_size ||
		   lock_info->last_mtime != st.st_mtime) {
		lock_info->last_change = now;
		lock_info->last_size = st.st_size;
		lock_info->last_mtime = st.st_mtime;
	}

	if (now > lock_info->last_change + (time_t)lock_info->stale_timeout) {
		/* no changes for a while, assume stale lock */
		if (unlink(lock_info->lock_path) < 0 && errno != ENOENT) {
			i_error("unlink(%s) failed: %m", lock_info->lock_path);
			return -1;
		}
		return 1;
	}

	return 0;
}

static int try_create_lock(const char *lock_path, struct dotlock *dotlock_r)
{
	const char *str;
	struct stat st;
	int fd;

	fd = open(lock_path, O_WRONLY | O_EXCL | O_CREAT, 0644);
	if (fd == -1)
		return -1;

	/* write our pid and host, if possible */
	str = t_strdup_printf("%s:%s", my_pid, my_hostname);
	if (write_full(fd, str, strlen(str)) < 0) {
		/* failed, leave it empty then */
		if (ftruncate(fd, 0) < 0) {
			i_error("ftruncate(%s) failed: %m", lock_path);
			(void)unlink(lock_path);
			(void)close(fd);
			return -1;
		}
	}

	/* save the inode info after writing */
	if (fstat(fd, &st) < 0) {
		i_error("fstat(%s) failed: %m", lock_path);
		(void)close(fd);
		return -1;
	}

	dotlock_r->dev = st.st_dev;
	dotlock_r->ino = st.st_ino;
	dotlock_r->mtime = st.st_mtime;

	if (close(fd) < 0) {
		i_error("close(%s) failed: %m", lock_path);
		(void)unlink(lock_path);
		return -1;
	}
	return 1;
}

int file_lock_dotlock(const char *path, int checkonly,
		      unsigned int timeout, unsigned int stale_timeout,
		      int (*callback)(unsigned int secs_left, int stale,
				      void *context),
		      void *context, struct dotlock *dotlock_r)
{
	const char *lock_path;
        struct lock_info lock_info;
	unsigned int stale_notify_threshold;
	time_t now, max_wait_time, last_notify;

	now = time(NULL);

	lock_path = t_strconcat(path, ".lock", NULL);
	stale_notify_threshold = stale_timeout / 2;
	max_wait_time = now + timeout;

	/* There's two ways to do this:

	   a) Rely on O_EXCL. Historically this hasn't always worked with NFS.
	   b) Create temp file and link() it to the file we want.

	   We now use a). It's easier to do and it never leaves temporary files
	   lying around. Also Postfix relies on it too, so I guess it's safe
	   enough nowadays.
	*/

	memset(&lock_info, 0, sizeof(lock_info));
	lock_info.path = path;
	lock_info.lock_path = lock_path;
	lock_info.stale_timeout = stale_timeout;
	lock_info.last_change = now;

	last_notify = 0;

	do {
		switch (check_lock(now, &lock_info)) {
		case -1:
			return -1;
		case 0:
			if (last_notify != now && callback != NULL) {
				unsigned int change_secs;
				unsigned int wait_left;

				last_notify = now;
				change_secs = now - lock_info.last_change;
				wait_left = max_wait_time - now;

				if (change_secs >= stale_notify_threshold &&
				    change_secs <= wait_left) {
					if (!callback(stale_timeout -
						      change_secs,
						      TRUE, context)) {
						/* we don't want to override */
						lock_info.last_change = now;
					}
				} else {
					(void)callback(wait_left, FALSE,
						       context);
				}
			}

			usleep(LOCK_RANDOM_USLEEP_TIME);
			break;
		default:
			if (checkonly ||
			    try_create_lock(lock_path, dotlock_r) > 0)
				return 1;

			if (errno != EEXIST) {
				i_error("open(%s) failed: %m", lock_path);
				return -1;
			}
			break;
		}

		now = time(NULL);
	} while (now < max_wait_time);

	errno = EAGAIN;
	return 0;
}

int file_unlock_dotlock(const char *path, const struct dotlock *dotlock)
{
	const char *lock_path;
	struct stat st;

	lock_path = t_strconcat(path, ".lock", NULL);

	if (lstat(lock_path, &st) < 0) {
		if (errno == ENOENT) {
			i_warning("Our dotlock file %s was deleted", lock_path);
			return 0;
		}

		i_error("lstat(%s) failed: %m", lock_path);
		return -1;
	}

	if (dotlock->ino != st.st_ino ||
	    !CMP_DEV_T(dotlock->dev, st.st_dev)) {
		i_warning("Our dotlock file %s was overridden", lock_path);
		return 0;
	}

	if (dotlock->mtime != st.st_mtime) {
		i_warning("Our dotlock file %s was modified (%s vs %s), "
			  "assuming it wasn't overridden", lock_path,
			  dec2str(dotlock->mtime), dec2str(st.st_mtime));
	}

	if (unlink(lock_path) < 0) {
		if (errno == ENOENT) {
			i_warning("Our dotlock file %s was deleted", lock_path);
			return 0;
		}

		i_error("unlink(%s) failed: %m", lock_path);
		return -1;
	}

	return 1;
}
