/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "file-lock.h"
#include "file-create-locked.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_RETRY_COUNT 1000

static int
try_lock_existing(int fd, const char *path,
		  const struct file_create_settings *set,
		  struct file_lock **lock_r, const char **error_r)
{
	struct stat st1, st2;
	int ret;

	if (fstat(fd, &st1) < 0) {
		*error_r = t_strdup_printf("fstat(%s) failed: %m", path);
		return -1;
	}
	if (file_wait_lock_error(fd, path, F_WRLCK, set->lock_method,
				 set->lock_timeout_secs, lock_r, error_r) <= 0)
		return -1;
	if (stat(path, &st2) == 0) {
		ret = st1.st_ino == st2.st_ino &&
			CMP_DEV_T(st1.st_dev, st2.st_dev) ? 1 : 0;
	} else if (errno == ENOENT) {
		ret = 0;
	} else {
		*error_r = t_strdup_printf("stat(%s) failed: %m", path);
		ret = -1;
	}
	if (ret <= 0) {
		/* the fd is closed next - no need to unlock */
		file_lock_free(lock_r);
	}
	return ret;
}

static int
try_create_new(const char *path, const struct file_create_settings *set,
	       int *fd_r, struct file_lock **lock_r,  const char **error_r)
{
	string_t *temp_path = t_str_new(128);
	int fd, orig_errno, ret = -1;
	int mode = set->mode != 0 ? set->mode : 0600;
	uid_t uid = set->uid != 0 ? set->uid : (uid_t)-1;
	uid_t gid = set->gid != 0 ? set->gid : (gid_t)-1;

	str_append(temp_path, path);
	if (uid != (uid_t)-1)
		fd = safe_mkstemp(temp_path, mode, uid, gid);
	else
		fd = safe_mkstemp_group(temp_path, mode, gid, set->gid_origin);
	if (fd == -1) {
		*error_r = t_strdup_printf("safe_mkstemp(%s) failed: %m", path);
		return -1;
	}
	if (file_try_lock_error(fd, str_c(temp_path), F_WRLCK,
				set->lock_method, lock_r, error_r) <= 0) {
	} else if (link(str_c(temp_path), path) < 0) {
		if (errno == EEXIST) {
			/* just created by somebody else */
			ret = 0;
		} else if (errno == ENOENT) {
			/* nobody should be deleting the temp file unless the
			   entire directory is deleted. */
			*error_r = t_strdup_printf(
				"Temporary file %s was unexpectedly deleted",
				str_c(temp_path));
		} else {
			*error_r = t_strdup_printf("link(%s, %s) failed: %m",
						   str_c(temp_path), path);
		}
		file_lock_free(lock_r);
	} else {
		i_unlink_if_exists(str_c(temp_path));
		*fd_r = fd;
		return 1;
	}
	orig_errno = errno;
	i_close_fd(&fd);
	i_unlink_if_exists(str_c(temp_path));
	errno = orig_errno;
	return ret;
}

int file_create_locked(const char *path, const struct file_create_settings *set,
		       struct file_lock **lock_r, bool *created_r,
		       const char **error_r)
{
	unsigned int i;
	int fd, ret;

	for (i = 0; i < MAX_RETRY_COUNT; i++) {
		fd = open(path, O_RDWR);
		if (fd != -1) {
			ret = try_lock_existing(fd, path, set, lock_r, error_r);
			if (ret > 0) {
				/* successfully locked an existing file */
				*created_r = FALSE;
				return fd;
			}
			i_close_fd(&fd);
			if (ret < 0)
				return -1;
		} else if (errno != ENOENT) {
			*error_r = t_strdup_printf("open(%s) failed: %m", path);
			return -1;
		} else {
			/* try to create the file */
			ret = try_create_new(path, set, &fd, lock_r, error_r);
			if (ret < 0)
				return -1;
			if (ret > 0) {
				/* successfully created a new locked file */
				*created_r = TRUE;
				return fd;
			}
			/* the file was just created - try again opening and
			   locking it */
		}
	}
	*error_r = t_strdup_printf("Creating a locked file %s keeps failing", path);
	errno = EINVAL;
	return -1;
}
