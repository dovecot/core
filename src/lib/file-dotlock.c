/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "randgen.h"
#include "write-full.h"
#include "file-dotlock.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>

/* 0.1 .. 0.2msec */
#define LOCK_RANDOM_USLEEP_TIME (100000 + (unsigned int)rand() % 100000)

struct lock_info {
	const char *path, *lock_path, *temp_path;
	unsigned int stale_timeout;
	unsigned int immediate_stale_timeout;
	int fd;

	dev_t dev;
	ino_t ino;
	off_t size;
	time_t ctime, mtime;

	off_t last_size;
	time_t last_ctime, last_mtime;
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

	if (lock_info->immediate_stale_timeout != 0 &&
	    now > st.st_mtime + (time_t)lock_info->immediate_stale_timeout &&
	    now > st.st_ctime + (time_t)lock_info->immediate_stale_timeout) {
		/* old lock file */
		if (unlink(lock_info->lock_path) < 0 && errno != ENOENT) {
			i_error("unlink(%s) failed: %m", lock_info->lock_path);
			return -1;
		}
		return 1;
	}

	if (lock_info->stale_timeout == 0) {
		/* no change checking */
		return 0;
	}

	if (lock_info->ino != st.st_ino ||
	    !CMP_DEV_T(lock_info->dev, st.st_dev) ||
	    lock_info->ctime != st.st_ctime ||
	    lock_info->mtime != st.st_mtime ||
	    lock_info->size != st.st_size) {
		/* either our first check or someone else got the lock file.
		   check if it contains a pid whose existence we can verify */
		lock_info->dev = st.st_dev;
		lock_info->ino = st.st_ino;
		lock_info->ctime = st.st_ctime;
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

	if (lock_info->last_change != now) {
		if (stat(lock_info->path, &st) < 0) {
			if (errno == ENOENT) {
				/* file doesn't exist. treat it as if
				   it hasn't changed */
			} else {
				i_error("stat(%s) failed: %m", lock_info->path);
				return -1;
			}
		} else if (lock_info->last_size != st.st_size ||
			   lock_info->last_ctime != st.st_ctime ||
			   lock_info->last_mtime != st.st_mtime) {
			lock_info->last_change = now;
			lock_info->last_size = st.st_size;
			lock_info->last_ctime = st.st_ctime;
			lock_info->last_mtime = st.st_mtime;
		}
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

static int create_temp_file(const char *prefix, const char **path_r)
{
	string_t *path;
	size_t len;
	struct stat st;
	char randbuf[8];
	int fd;

	path = t_str_new(256);
	str_append(path, prefix);
	len = str_len(path);

	for (;;) {
		do {
			random_fill(randbuf, sizeof(randbuf));
			str_truncate(path, len);
			str_append(path,
				   binary_to_hex(randbuf, sizeof(randbuf)));
			*path_r = str_c(path);
		} while (stat(*path_r, &st) == 0);

		if (errno != ENOENT) {
			i_error("stat(%s) failed: %m", *path_r);
			return -1;
		}

		fd = open(*path_r, O_RDWR | O_EXCL | O_CREAT, 0666);
		if (fd != -1)
			return fd;

		if (errno != EEXIST) {
			i_error("open(%s) failed: %m", *path_r);
			return -1;
		}
	}
}

static int try_create_lock(struct lock_info *lock_info, const char *temp_prefix)
{
	const char *str, *p;

	if (lock_info->temp_path == NULL) {
		/* we'll need our temp file first. */
		if (temp_prefix == NULL) {
			temp_prefix = t_strconcat(".temp.", my_hostname, ".",
						  my_pid, ".", NULL);
		}

		p = *temp_prefix == '/' ? NULL :
			strrchr(lock_info->lock_path, '/');
		if (p != NULL) {
			str = t_strdup_until(lock_info->lock_path, p+1);
			temp_prefix = t_strconcat(str, temp_prefix, NULL);
		}

		lock_info->fd = create_temp_file(temp_prefix, &str);
		if (lock_info->fd == -1)
			return -1;

                lock_info->temp_path = str;
	}

	if (link(lock_info->temp_path, lock_info->lock_path) < 0) {
		if (errno == EEXIST)
			return 0;

		i_error("link(%s, %s) failed: %m",
			lock_info->temp_path, lock_info->lock_path);
		return -1;
	}

	if (unlink(lock_info->temp_path) < 0 && errno != ENOENT) {
		i_error("unlink(%s) failed: %m", lock_info->temp_path);
		/* non-fatal, continue */
	}
	lock_info->temp_path = NULL;

	return 1;
}

static int dotlock_create(const char *path, const char *temp_prefix,
			  int checkonly, int *fd,
			  unsigned int timeout, unsigned int stale_timeout,
			  unsigned int immediate_stale_timeout,
			  int (*callback)(unsigned int secs_left, int stale,
					  void *context),
			  void *context)
{
	const char *lock_path;
        struct lock_info lock_info;
	unsigned int stale_notify_threshold;
	unsigned int change_secs, wait_left;
	time_t now, max_wait_time, last_notify;
	int do_wait, ret;

	now = time(NULL);

	lock_path = t_strconcat(path, ".lock", NULL);
	stale_notify_threshold = stale_timeout / 2;
	max_wait_time = now + timeout;

	memset(&lock_info, 0, sizeof(lock_info));
	lock_info.path = path;
	lock_info.lock_path = lock_path;
	lock_info.stale_timeout = stale_timeout;
	lock_info.immediate_stale_timeout = immediate_stale_timeout;
	lock_info.last_change = now;
	lock_info.fd = -1;

	last_notify = 0; do_wait = FALSE;

	do {
		if (do_wait) {
			usleep(LOCK_RANDOM_USLEEP_TIME);
			do_wait = FALSE;
		}

		ret = check_lock(now, &lock_info);
		if (ret < 0)
			break;

		if (ret == 1) {
			if (checkonly)
				break;

			ret = try_create_lock(&lock_info, temp_prefix);
			if (ret != 0)
				break;
		}

		do_wait = TRUE;
		if (last_notify != now && callback != NULL) {
			last_notify = now;
			change_secs = now - lock_info.last_change;
			wait_left = max_wait_time - now;

			t_push();
			if (change_secs >= stale_notify_threshold &&
			    change_secs <= wait_left) {
				if (!callback(stale_timeout - change_secs,
					      TRUE, context)) {
					/* we don't want to override */
					lock_info.last_change = now;
				}
			} else {
				(void)callback(wait_left, FALSE, context);
			}
			t_pop();
		}

		now = time(NULL);
	} while (now < max_wait_time);

	if (ret <= 0 && lock_info.fd != -1) {
		int old_errno = errno;

		(void)close(lock_info.fd);
		lock_info.fd = -1;
		errno = old_errno;
	}
	*fd = lock_info.fd;

	if (ret == 0)
		errno = EAGAIN;
	return ret;
}

int file_lock_dotlock(const char *path, const char *temp_prefix, int checkonly,
		      unsigned int timeout, unsigned int stale_timeout,
		      unsigned int immediate_stale_timeout,
		      int (*callback)(unsigned int secs_left, int stale,
				      void *context),
		      void *context, struct dotlock *dotlock_r)
{
	const char *lock_path, *str;
	struct stat st;
	int fd, ret;

	lock_path = t_strconcat(path, ".lock", NULL);

	ret = dotlock_create(path, temp_prefix, checkonly, &fd,
			     timeout, stale_timeout, immediate_stale_timeout,
			     callback, context);
	if (ret <= 0 || checkonly)
		return ret;

	/* write our pid and host, if possible */
	str = t_strdup_printf("%s:%s", my_pid, my_hostname);
	if (write_full(fd, str, strlen(str)) < 0) {
		/* failed, leave it empty then */
		if (ftruncate(fd, 0) < 0) {
			i_error("ftruncate(%s) failed: %m", lock_path);
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

	if (close(fd) < 0) {
		i_error("fstat(%s) failed: %m", lock_path);
		return -1;
	}

	dotlock_r->dev = st.st_dev;
	dotlock_r->ino = st.st_ino;
	dotlock_r->mtime = st.st_mtime;
	return 1;
}

static int dotlock_delete(const char *path, const struct dotlock *dotlock)
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

int file_unlock_dotlock(const char *path, const struct dotlock *dotlock)
{
	return dotlock_delete(path, dotlock);
}

int file_dotlock_open(const char *path, const char *temp_prefix,
		      unsigned int timeout, unsigned int stale_timeout,
		      unsigned int immediate_stale_timeout,
		      int (*callback)(unsigned int secs_left, int stale,
				      void *context),
		      void *context)
{
	int ret, fd;

	ret = dotlock_create(path, temp_prefix, FALSE, &fd,
			     timeout, stale_timeout, immediate_stale_timeout,
			     callback, context);
	if (ret <= 0)
		return -1;
	return fd;
}

int file_dotlock_replace(const char *path, int fd, int verify_owner)
{
	struct stat st, st2;
	const char *lock_path;

	lock_path = t_strconcat(path, ".lock", NULL);
	if (verify_owner) {
		if (fstat(fd, &st) < 0) {
			i_error("fstat(%s) failed: %m", lock_path);
			(void)close(fd);
			return -1;
		}
	}
	if (close(fd) < 0) {
		i_error("close(%s) failed: %m", lock_path);
		return -1;
	}

	if (verify_owner) {
		if (lstat(lock_path, &st2) < 0) {
			i_error("lstat(%s) failed: %m", lock_path);
			return -1;
		}

		if (st.st_ino != st2.st_ino ||
		    !CMP_DEV_T(st.st_dev, st2.st_dev)) {
			i_warning("Our dotlock file %s was overridden",
				  lock_path);
			return 0;
		}
	}

	if (rename(lock_path, path) < 0) {
		i_error("rename(%s, %s) failed: %m", lock_path, path);
		return -1;
	}
	return 1;
}

int file_dotlock_delete(const char *path, int fd)
{
	struct dotlock dotlock;
	struct stat st;

	if (fstat(fd, &st) < 0) {
		i_error("fstat(%s) failed: %m",
			t_strconcat(path, ".lock", NULL));
		(void)close(fd);
		return -1;
	}

	if (close(fd) < 0) {
		i_error("close(%s) failed: %m",
			t_strconcat(path, ".lock", NULL));
		return -1;
	}

	dotlock.dev = st.st_dev;
	dotlock.ino = st.st_ino;
	dotlock.mtime = st.st_mtime;

	return dotlock_delete(path, &dotlock);
}
