/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "safe-mkstemp.h"
#include "mkdir-parents.h"
#include "write-full.h"
#include "file-lock.h"
#include "file-dotlock.h"
#include "fs-api-private.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define FS_POSIX_DOTLOCK_STALE_TIMEOUT_SECS (60*10)
#define MAX_MKDIR_RETRY_COUNT 5

enum fs_posix_lock_method {
	FS_POSIX_LOCK_METHOD_FLOCK,
	FS_POSIX_LOCK_METHOD_DOTLOCK
};

struct posix_fs {
	struct fs fs;
	char *temp_file_prefix;
	enum fs_posix_lock_method lock_method;
};

struct posix_fs_file {
	struct fs_file file;
	char *temp_path;
	int fd;
	enum fs_open_mode open_mode;
	enum fs_open_flags open_flags;

	buffer_t *write_buf;

	bool seek_to_beginning;
	bool success;
};

struct posix_fs_lock {
	struct fs_lock lock;
	struct file_lock *file_lock;
	struct dotlock *dotlock;
};

static struct fs *
fs_posix_init(const char *args, const struct fs_settings *set)
{
	struct posix_fs *fs;

	fs = i_new(struct posix_fs, 1);
	fs->fs = fs_class_posix;
	fs->temp_file_prefix = set->temp_file_prefix != NULL ?
		i_strdup(set->temp_file_prefix) : i_strdup("temp.dovecot.");
	fs->fs.set.temp_file_prefix = fs->temp_file_prefix;

	if (*args == '\0')
		fs->lock_method = FS_POSIX_LOCK_METHOD_FLOCK;
	else if (strcmp(args, "lock=flock") == 0)
		fs->lock_method = FS_POSIX_LOCK_METHOD_FLOCK;
	else if (strcmp(args, "lock=dotlock") == 0)
		fs->lock_method = FS_POSIX_LOCK_METHOD_DOTLOCK;
	else
		i_fatal("fs-posix: Unknown args '%s'", args);
	return &fs->fs;
}

static void fs_posix_deinit(struct fs *_fs)
{
	struct posix_fs *fs = (struct posix_fs *)_fs;

	i_free(fs->temp_file_prefix);
	i_free(fs);
}

static int fs_posix_create_parent_dir(struct fs *fs, const char *path)
{
	const char *dir, *fname;

	fname = strrchr(path, '/');
	if (fname == NULL)
		return 1;
	dir = t_strdup_until(path, fname);
	if (mkdir_parents(dir, 0700) == 0)
		return 0;
	else if (errno == EEXIST)
		return 1;
	else {
		fs_set_error(fs, "mkdir_parents(%s) failed: %m", dir);
		return -1;
	}
}

static int
fs_posix_create(struct posix_fs *fs, const char *path, enum fs_open_flags flags,
		char **temp_path_r)
{
	struct fs *_fs = &fs->fs;
	string_t *str = t_str_new(256);
	const char *slash = strrchr(path, '/');
	unsigned int try_count = 0;
	int fd;

	if (slash != NULL)
		str_append_n(str, path, slash-path + 1);
	str_append(str, fs->temp_file_prefix);

	fd = safe_mkstemp_hostpid(str, 0600, (uid_t)-1, (gid_t)-1);
	while (fd == -1 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT &&
	       (flags & FS_OPEN_FLAG_MKDIR) != 0) {
		if (fs_posix_create_parent_dir(_fs, path) < 0)
			return -1;
		fd = safe_mkstemp_hostpid(str, 0600, (uid_t)-1, (gid_t)-1);
		try_count++;
	}
	if (fd == -1) {
		fs_set_error(_fs, "safe_mkstemp(%s) failed: %m", str_c(str));
		return -1;
	}
	*temp_path_r = i_strdup(str_c(str));
	return fd;
}

static int
fs_posix_open(struct fs *_fs, const char *path, enum fs_open_mode mode,
	      enum fs_open_flags flags, struct fs_file **file_r)
{
	struct posix_fs *fs = (struct posix_fs *)_fs;
	struct posix_fs_file *file;
	char *temp_path = NULL;
	int fd = -1;

	switch (mode) {
	case FS_OPEN_MODE_RDONLY:
		fd = open(path, O_RDONLY);
		if (fd == -1)
			fs_set_error(_fs, "open(%s) failed: %m", path);
		break;
	case FS_OPEN_MODE_APPEND:
		fd = open(path, O_RDWR | O_APPEND);
		if (fd == -1)
			fs_set_error(_fs, "open(%s) failed: %m", path);
		break;
	case FS_OPEN_MODE_CREATE:
	case FS_OPEN_MODE_REPLACE:
		T_BEGIN {
			fd = fs_posix_create(fs, path, flags, &temp_path);
		} T_END;
		break;
	}
	if (fd == -1)
		return -1;

	file = i_new(struct posix_fs_file, 1);
	file->file.fs = _fs;
	file->file.path = i_strdup(path);
	file->open_mode = mode;
	file->open_flags = flags;
	file->temp_path = temp_path;
	file->fd = fd;

	*file_r = &file->file;
	return 0;
}

static void fs_posix_close(struct fs_file *_file)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	i_assert(_file->output == NULL);

	switch (file->open_mode) {
	case FS_OPEN_MODE_RDONLY:
	case FS_OPEN_MODE_APPEND:
		break;
	case FS_OPEN_MODE_CREATE:
	case FS_OPEN_MODE_REPLACE:
		if (file->success)
			break;
		/* failed to create/replace this. delete the temp file */
		if (unlink(file->temp_path) < 0) {
			fs_set_critical(_file->fs, "unlink(%s) failed: %m",
					file->temp_path);
		}
		break;
	}

	if (file->fd != -1) {
		if (close(file->fd) < 0) {
			fs_set_critical(_file->fs, "close(%s) failed: %m",
					_file->path);
		}
	}
	i_free(file->temp_path);
	i_free(file->file.path);
	i_free(file);
}

static ssize_t fs_posix_read(struct fs_file *_file, void *buf, size_t size)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	ssize_t ret;

	if (file->seek_to_beginning) {
		file->seek_to_beginning = FALSE;
		if (lseek(file->fd, 0, SEEK_SET) < 0) {
			fs_set_critical(_file->fs, "lseek(%s, 0) failed: %m",
					_file->path);
			return -1;
		}
	}

	ret = read(file->fd, buf, size);
	if (ret < 0)
		fs_set_error(_file->fs, "read(%s) failed: %m", _file->path);
	return ret;
}

static struct istream *
fs_posix_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	return i_stream_create_fd(file->fd, max_buffer_size, FALSE);
}

static int fs_posix_write_finish(struct posix_fs_file *file)
{
	int ret;

	if ((file->open_flags & FS_OPEN_FLAG_FDATASYNC) != 0) {
		if (fs_fdatasync(&file->file) < 0)
			return -1;
	}

	if (close(file->fd) < 0) {
		file->fd = -1;
		fs_set_error(file->file.fs, "close(%s) failed: %m",
			     file->file.path);
		return -1;
	}
	file->fd = -1;

	switch (file->open_mode) {
	case FS_OPEN_MODE_CREATE:
		if ((ret = link(file->temp_path, file->file.path)) < 0) {
			fs_set_error(file->file.fs, "link(%s, %s) failed: %m",
				     file->temp_path, file->file.path);
		}
		if (unlink(file->temp_path) < 0) {
			fs_set_error(file->file.fs, "unlink(%s) failed: %m",
				     file->temp_path);
		}
		if (ret < 0)
			return -1;
		break;
	case FS_OPEN_MODE_REPLACE:
		if (rename(file->temp_path, file->file.path) < 0) {
			fs_set_error(file->file.fs, "rename(%s, %s) failed: %m",
				     file->temp_path, file->file.path);
			return -1;
		}
		break;
	default:
		i_unreached();
	}
	file->success = TRUE;
	file->seek_to_beginning = TRUE;
	return 0;
}

static int fs_posix_write(struct fs_file *_file, const void *data, size_t size)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	ssize_t ret;

	if (file->open_mode != FS_OPEN_MODE_APPEND) {
		if (write_full(file->fd, data, size) < 0) {
			fs_set_error(_file->fs, "write(%s) failed: %m",
				     _file->path);
			return -1;
		}
		return fs_posix_write_finish(file);
	}

	/* atomic append - it should either succeed or fail */
	ret = write(file->fd, data, size);
	if (ret < 0) {
		fs_set_error(_file->fs, "write(%s) failed: %m", _file->path);
		return -1;
	}
	if ((size_t)ret != size) {
		fs_set_error(_file->fs,
			     "write(%s) returned %"PRIuSIZE_T"/%"PRIuSIZE_T,
			     _file->path, (size_t)ret, size);
		errno = ENOSPC;
		return -1;
	}
	return 0;
}

static void fs_posix_write_stream(struct fs_file *_file)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	i_assert(_file->output == NULL);

	if (file->open_mode == FS_OPEN_MODE_APPEND) {
		file->write_buf = buffer_create_dynamic(default_pool, 1024*32);
		_file->output = o_stream_create_buffer(file->write_buf);
		return;
	}

	_file->output = o_stream_create_fd_file(file->fd, (uoff_t)-1, FALSE);
}

static int fs_posix_write_stream_finish(struct fs_file *_file, bool success)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	int ret = success ? 0 : -1;

	(void)o_stream_flush(_file->output);
	if (_file->output->last_failed_errno < 0) {
		errno = _file->output->last_failed_errno;
		fs_set_error(_file->fs, "write(%s) failed: %m",
			     o_stream_get_name(_file->output));
		ret = -1;
	}
	o_stream_destroy(&_file->output);

	switch (file->open_mode) {
	case FS_OPEN_MODE_APPEND:
		if (ret == 0) {
			ret = fs_posix_write(_file, file->write_buf->data,
					     file->write_buf->used);
		}
		buffer_free(&file->write_buf);
		break;
	case FS_OPEN_MODE_CREATE:
	case FS_OPEN_MODE_REPLACE:
		if (ret == 0)
			ret = fs_posix_write_finish(file);
		break;
	case FS_OPEN_MODE_RDONLY:
		i_unreached();
	}
	return ret;
}

static int
fs_posix_lock(struct fs_file *_file, unsigned int secs, struct fs_lock **lock_r)
{
#ifdef HAVE_FLOCK
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
#endif
	struct posix_fs *fs = (struct posix_fs *)_file->fs;
	struct dotlock_settings dotlock_set;
	struct posix_fs_lock fs_lock, *ret_lock;
	int ret = -1;

	memset(&fs_lock, 0, sizeof(fs_lock));
	fs_lock.lock.file = _file;

	switch (fs->lock_method) {
	case FS_POSIX_LOCK_METHOD_FLOCK:
#ifndef HAVE_FLOCK
		fs_set_error(_file->fs, "flock() not supported by OS "
			     "(for file %s)", _file->path);
#else
		if (secs == 0) {
			ret = file_try_lock(file->fd, _file->path, F_WRLCK,
					    FILE_LOCK_METHOD_FLOCK,
					    &fs_lock.file_lock);
		} else {
			ret = file_wait_lock(file->fd, _file->path, F_WRLCK,
					     FILE_LOCK_METHOD_FLOCK, secs,
					     &fs_lock.file_lock);
		}
		if (ret < 0) {
			fs_set_error(_file->fs, "flock(%s) failed: %m",
				     _file->path);
		}
#endif
		break;
	case FS_POSIX_LOCK_METHOD_DOTLOCK:
		memset(&dotlock_set, 0, sizeof(dotlock_set));
		dotlock_set.stale_timeout = FS_POSIX_DOTLOCK_STALE_TIMEOUT_SECS;
		dotlock_set.use_excl_lock = TRUE;
		dotlock_set.timeout = secs;

		ret = file_dotlock_create(&dotlock_set, _file->path,
					  secs == 0 ? 0 :
					  DOTLOCK_CREATE_FLAG_NONBLOCK,
					  &fs_lock.dotlock);
		if (ret < 0) {
			fs_set_error(_file->fs,
				     "file_dotlock_create(%s) failed: %m",
				     _file->path);
		}
		break;
	}
	if (ret <= 0)
		return ret;

	ret_lock = i_new(struct posix_fs_lock, 1);
	*ret_lock = fs_lock;
	*lock_r = &ret_lock->lock;
	return 1;
}

static void fs_posix_unlock(struct fs_lock *_lock)
{
	struct posix_fs_lock *lock = (struct posix_fs_lock *)_lock;

	if (lock->file_lock != NULL)
		file_unlock(&lock->file_lock);
	if (lock->dotlock != NULL)
		(void)file_dotlock_delete(&lock->dotlock);
	i_free(lock);
}

static int fs_posix_fdatasync(struct fs_file *_file)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	if (fdatasync(file->fd) < 0) {
		fs_set_error(_file->fs, "fdatasync(%s) failed: %m",
			     _file->path);
		return -1;
	}
	return 0;
}

static int fs_posix_exists(struct fs *fs, const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0) {
		if (errno != ENOENT) {
			fs_set_error(fs, "stat(%s) failed: %m", path);
			return -1;
		}
		return 0;
	}
	return 1;
}

static int fs_posix_stat(struct fs *fs, const char *path, struct stat *st_r)
{
	if (stat(path, st_r) < 0) {
		fs_set_error(fs, "stat(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

static int fs_posix_link(struct fs *fs, const char *src, const char *dest)
{
	unsigned int try_count = 0;
	int ret;

	ret = link(src, dest);
	while (ret < 0 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT) {
		if (fs_posix_create_parent_dir(fs, dest) < 0)
			return -1;
		ret = link(src, dest);
		try_count++;
	}
	if (ret < 0) {
		fs_set_error(fs, "link(%s, %s) failed: %m", src, dest);
		return -1;
	}
	return 0;
}

static int fs_posix_rename(struct fs *fs, const char *src, const char *dest)
{
	unsigned int try_count = 0;
	int ret;

	ret = rename(src, dest);
	while (ret < 0 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT) {
		if (fs_posix_create_parent_dir(fs, dest) < 0)
			return -1;
		ret = rename(src, dest);
		try_count++;
	}
	if (ret < 0) {
		fs_set_error(fs, "link(%s, %s) failed: %m", src, dest);
		return -1;
	}
	return 0;
}

static int fs_posix_unlink(struct fs *fs, const char *path)
{
	if (unlink(path) < 0) {
		fs_set_error(fs, "unlink(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

static int fs_posix_rmdir(struct fs *fs, const char *path)
{
	if (rmdir(path) < 0) {
		fs_set_error(fs, "rmdir(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

struct fs fs_class_posix = {
	.name = "posix",
	.v = {
		fs_posix_init,
		fs_posix_deinit,
		fs_posix_open,
		fs_posix_close,
		fs_posix_read,
		fs_posix_read_stream,
		fs_posix_write,
		fs_posix_write_stream,
		fs_posix_write_stream_finish,
		fs_posix_lock,
		fs_posix_unlock,
		fs_posix_fdatasync,
		fs_posix_exists,
		fs_posix_stat,
		fs_posix_link,
		fs_posix_rename,
		fs_posix_unlink,
		fs_posix_rmdir
	}
};
