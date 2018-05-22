/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "guid.h"
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
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#define FS_POSIX_DOTLOCK_STALE_TIMEOUT_SECS (60*10)
#define MAX_MKDIR_RETRY_COUNT 5
#define FS_DEFAULT_MODE 0600

enum fs_posix_lock_method {
	FS_POSIX_LOCK_METHOD_FLOCK,
	FS_POSIX_LOCK_METHOD_DOTLOCK
};

struct posix_fs {
	struct fs fs;
	char *temp_file_prefix, *root_path, *path_prefix;
	size_t temp_file_prefix_len;
	enum fs_posix_lock_method lock_method;
	mode_t mode;
	bool mode_auto;
	bool have_dirs;
	bool disable_fsync;
	bool accurate_mtime;
};

struct posix_fs_file {
	struct fs_file file;
	char *temp_path, *full_path;
	int fd;
	enum fs_open_mode open_mode;
	enum fs_open_flags open_flags;

	buffer_t *write_buf;

	bool seek_to_beginning;
};

struct posix_fs_lock {
	struct fs_lock lock;
	struct file_lock *file_lock;
	struct dotlock *dotlock;
};

struct posix_fs_iter {
	struct fs_iter iter;
	char *path;
	DIR *dir;
	int err;
};

static struct fs *fs_posix_alloc(void)
{
	struct posix_fs *fs;

	fs = i_new(struct posix_fs, 1);
	fs->fs = fs_class_posix;
	return &fs->fs;
}

static int
fs_posix_init(struct fs *_fs, const char *args, const struct fs_settings *set)
{
	struct posix_fs *fs = (struct posix_fs *)_fs;
	const char *const *tmp;

	fs->temp_file_prefix = set->temp_file_prefix != NULL ?
		i_strdup(set->temp_file_prefix) : i_strdup("temp.dovecot.");
	fs->temp_file_prefix_len = strlen(fs->temp_file_prefix);
	fs->root_path = i_strdup(set->root_path);
	fs->fs.set.temp_file_prefix = fs->temp_file_prefix;
	fs->fs.set.root_path = fs->root_path;

	fs->lock_method = FS_POSIX_LOCK_METHOD_FLOCK;
	fs->mode = FS_DEFAULT_MODE;

	tmp = t_strsplit_spaces(args, ":");
	for (; *tmp != NULL; tmp++) {
		const char *arg = *tmp;

		if (strcmp(arg, "lock=flock") == 0)
			fs->lock_method = FS_POSIX_LOCK_METHOD_FLOCK;
		else if (strcmp(arg, "lock=dotlock") == 0)
			fs->lock_method = FS_POSIX_LOCK_METHOD_DOTLOCK;
		else if (str_begins(arg, "prefix=")) {
			i_free(fs->path_prefix);
			fs->path_prefix = i_strdup(arg + 7);
		} else if (strcmp(arg, "mode=auto") == 0) {
			fs->mode_auto = TRUE;
		} else if (strcmp(arg, "dirs") == 0) {
			fs->have_dirs = TRUE;
		} else if (strcmp(arg, "no-fsync") == 0) {
			fs->disable_fsync = TRUE;
		} else if (strcmp(arg, "accurate-mtime") == 0) {
			fs->accurate_mtime = TRUE;
		} else if (str_begins(arg, "mode=")) {
			unsigned int mode;
			if (str_to_uint_oct(arg+5, &mode) < 0) {
				fs_set_error(_fs, "Invalid mode value: %s", arg+5);
				return -1;
			}
			fs->mode = mode & 0666;
			if (fs->mode == 0) {
				fs_set_error(_fs, "Invalid mode: %s", arg+5);
				return -1;
			}
		} else {
			fs_set_error(_fs, "Unknown arg '%s'", arg);
			return -1;
		}
	}
	return 0;
}

static void fs_posix_deinit(struct fs *_fs)
{
	struct posix_fs *fs = (struct posix_fs *)_fs;

	i_free(fs->temp_file_prefix);
	i_free(fs->root_path);
	i_free(fs->path_prefix);
	i_free(fs);
}

static enum fs_properties fs_posix_get_properties(struct fs *_fs)
{
	struct posix_fs *fs = (struct posix_fs *)_fs;
	enum fs_properties props =
		FS_PROPERTY_LOCKS | FS_PROPERTY_FASTCOPY | FS_PROPERTY_RENAME |
		FS_PROPERTY_STAT | FS_PROPERTY_ITER | FS_PROPERTY_RELIABLEITER;

	/* FS_PROPERTY_DIRECTORIES is not returned normally because fs_delete()
	   automatically rmdir()s parents. For backwards compatibility
	   (especially with SIS code) we'll do it that way, but optionally with
	   "dirs" parameter enable them. This is especially important to be
	   able to use doveadm fs commands to delete empty directories. */
	if (fs->have_dirs)
		props |= FS_PROPERTY_DIRECTORIES;
	return props;
}

static int
fs_posix_get_mode(struct posix_fs *fs, const char *path, mode_t *mode_r)
{
	struct stat st;
	const char *p;

	*mode_r = fs->mode;

	while (stat(path, &st) < 0) {
		if (errno != ENOENT) {
			fs_set_error(&fs->fs, "stat(%s) failed: %m", path);
			return -1;
		}
		p = strrchr(path, '/');
		if (p != NULL)
			path = t_strdup_until(path, p);
		else if (strcmp(path, ".") != 0)
			path = ".";
		else
			return 0;
	}
	if ((st.st_mode & S_ISGID) != 0) {
		/* setgid set - copy mode from parent */
		*mode_r = st.st_mode & 0666;
	}
	return 0;
}

static int fs_posix_mkdir_parents(struct posix_fs *fs, const char *path)
{
	const char *dir, *fname;
	mode_t mode, dir_mode;

	fname = strrchr(path, '/');
	if (fname == NULL)
		return 1;
	dir = t_strdup_until(path, fname);

	if (fs_posix_get_mode(fs, dir, &mode) < 0)
		return -1;
	dir_mode = mode;
	if ((dir_mode & 0600) != 0) dir_mode |= 0100;
	if ((dir_mode & 0060) != 0) dir_mode |= 0010;
	if ((dir_mode & 0006) != 0) dir_mode |= 0001;

	if (mkdir_parents(dir, dir_mode) == 0)
		return 0;
	else if (errno == EEXIST)
		return 1;
	else {
		fs_set_error(&fs->fs, "mkdir_parents(%s) failed: %m", dir);
		return -1;
	}
}

static int fs_posix_rmdir_parents(struct posix_fs *fs, const char *path)
{
	const char *p;

	if (fs->have_dirs)
		return 0;
	if (fs->root_path == NULL && fs->path_prefix == NULL)
		return 0;

	while ((p = strrchr(path, '/')) != NULL) {
		path = t_strdup_until(path, p);
		if ((fs->root_path != NULL && strcmp(path, fs->root_path) == 0) ||
		    (fs->path_prefix != NULL && str_begins(fs->path_prefix, path)))
			break;
		if (rmdir(path) == 0) {
			/* success, continue to parent */
		} else if (errno == ENOTEMPTY || errno == EEXIST) {
			/* there are other entries in this directory */
			break;
		} else if (errno == EBUSY || errno == ENOENT) {
			/* some other not-unexpected error */
			break;
		} else {
			fs_set_error(&fs->fs, "rmdir(%s) failed: %m", path);
			return -1;
		}
	}
	return 0;
}

static int fs_posix_create(struct posix_fs_file *file)
{
	struct posix_fs *fs = (struct posix_fs *)file->file.fs;
	string_t *str = t_str_new(256);
	const char *slash;
	unsigned int try_count = 0;
	mode_t mode;
	int fd;

	i_assert(file->temp_path == NULL);

	if ((slash = strrchr(file->full_path, '/')) != NULL) {
		str_append_data(str, file->full_path, slash - file->full_path);
		if (fs_posix_get_mode(fs, str_c(str), &mode) < 0)
			return -1;
		str_append_c(str, '/');
	} else {
		if (fs_posix_get_mode(fs, ".", &mode) < 0)
			return -1;
	}
	str_append(str, fs->temp_file_prefix);

	fd = safe_mkstemp_hostpid(str, mode, (uid_t)-1, (gid_t)-1);
	while (fd == -1 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT) {
		if (fs_posix_mkdir_parents(fs, str_c(str)) < 0)
			return -1;
		fd = safe_mkstemp_hostpid(str, mode, (uid_t)-1, (gid_t)-1);
		try_count++;
	}
	if (fd == -1) {
		fs_set_error(&fs->fs, "safe_mkstemp(%s) failed: %m", str_c(str));
		return -1;
	}
	file->temp_path = i_strdup(str_c(str));
	return fd;
}

static int fs_posix_open(struct posix_fs_file *file)
{
	struct posix_fs *fs = (struct posix_fs *)file->file.fs;
	const char *path = file->full_path;

	i_assert(file->fd == -1);

	switch (file->open_mode) {
	case FS_OPEN_MODE_READONLY:
		file->fd = open(path, O_RDONLY);
		if (file->fd == -1)
			fs_set_error(&fs->fs, "open(%s) failed: %m", path);
		break;
	case FS_OPEN_MODE_APPEND:
		file->fd = open(path, O_RDWR | O_APPEND);
		if (file->fd == -1)
			fs_set_error(&fs->fs, "open(%s) failed: %m", path);
		break;
	case FS_OPEN_MODE_CREATE_UNIQUE_128:
	case FS_OPEN_MODE_CREATE:
	case FS_OPEN_MODE_REPLACE:
		T_BEGIN {
			file->fd = fs_posix_create(file);
		} T_END;
		break;
	}
	if (file->fd == -1)
		return -1;
	return 0;
}

static struct fs_file *fs_posix_file_alloc(void)
{
	struct posix_fs_file *file = i_new(struct posix_fs_file, 1);
	return &file->file;
}

static void
fs_posix_file_init(struct fs_file *_file, const char *path,
		   enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	struct posix_fs *fs = (struct posix_fs *)_file->fs;
	guid_128_t guid;
	size_t path_len = strlen(path);

	if (path_len > 0 && path[path_len-1] == '/') {
		/* deleting "path/" (used e.g. by doveadm fs delete) - strip
		   out the trailing "/" since it doesn't work well with NFS. */
		path = t_strndup(path, path_len-1);
	}

	if (mode != FS_OPEN_MODE_CREATE_UNIQUE_128)
		file->file.path = i_strdup(path);
	else {
		guid_128_generate(guid);
		file->file.path = i_strdup_printf("%s/%s", path,
						  guid_128_to_string(guid));
	}
	file->full_path = fs->path_prefix == NULL ? i_strdup(file->file.path) :
		i_strconcat(fs->path_prefix, file->file.path, NULL);
	file->open_mode = mode;
	file->open_flags = flags;
	file->fd = -1;
}

static void fs_posix_file_close(struct fs_file *_file)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	if (file->fd != -1 && file->file.output == NULL) {
		if (close(file->fd) < 0) {
			fs_set_critical(file->file.fs, "close(%s) failed: %m",
					file->full_path);
		}
		file->fd = -1;
	}
}

static void fs_posix_file_deinit(struct fs_file *_file)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	i_assert(_file->output == NULL);

	switch (file->open_mode) {
	case FS_OPEN_MODE_READONLY:
	case FS_OPEN_MODE_APPEND:
		break;
	case FS_OPEN_MODE_CREATE_UNIQUE_128:
	case FS_OPEN_MODE_CREATE:
	case FS_OPEN_MODE_REPLACE:
		if (file->temp_path == NULL)
			break;
		/* failed to create/replace this. delete the temp file */
		if (unlink(file->temp_path) < 0) {
			fs_set_critical(_file->fs, "unlink(%s) failed: %m",
					file->temp_path);
		}
		break;
	}

	i_free(file->temp_path);
	i_free(file->full_path);
	i_free(file->file.path);
	i_free(file);
}

static int fs_posix_open_for_read(struct posix_fs_file *file)
{
	i_assert(file->file.output == NULL);
	i_assert(file->temp_path == NULL);

	if (file->fd == -1) {
		if (fs_posix_open(file) < 0)
			return -1;
	}
	return 0;
}

static bool fs_posix_prefetch(struct fs_file *_file, uoff_t length ATTR_UNUSED)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	if (fs_posix_open_for_read(file) < 0)
		return TRUE;

/* HAVE_POSIX_FADVISE alone isn't enough for CentOS 4.9 */
#if defined(HAVE_POSIX_FADVISE) && defined(POSIX_FADV_WILLNEED)
	if (posix_fadvise(file->fd, 0, length, POSIX_FADV_WILLNEED) < 0) {
		e_error(_file->event, "posix_fadvise(%s) failed: %m", file->full_path);
		return TRUE;
	}
#endif
	return FALSE;
}

static ssize_t fs_posix_read(struct fs_file *_file, void *buf, size_t size)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	ssize_t ret;

	if (fs_posix_open_for_read(file) < 0)
		return -1;

	if (file->seek_to_beginning) {
		file->seek_to_beginning = FALSE;
		if (lseek(file->fd, 0, SEEK_SET) < 0) {
			fs_set_critical(_file->fs, "lseek(%s, 0) failed: %m",
					file->full_path);
			return -1;
		}
	}

	ret = read(file->fd, buf, size);
	if (ret < 0)
		fs_set_error(_file->fs, "read(%s) failed: %m", file->full_path);
	fs_posix_file_close(_file);
	return ret;
}

static struct istream *
fs_posix_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	struct istream *input;

	if (fs_posix_open_for_read(file) < 0)
		input = i_stream_create_error_str(errno, "%s", fs_last_error(_file->fs));
	else {
		/* the stream could live even after the fs_file */
		input = i_stream_create_fd_autoclose(&file->fd, max_buffer_size);
	}
	i_stream_set_name(input, file->full_path);
	return input;
}

static void fs_posix_write_rename_if_needed(struct posix_fs_file *file)
{
	struct posix_fs *fs = (struct posix_fs *)file->file.fs;
	const char *new_fname;

	new_fname = fs_metadata_find(&file->file.metadata, FS_METADATA_WRITE_FNAME);
	if (new_fname == NULL)
		return;

	i_free(file->file.path);
	file->file.path = i_strdup(new_fname);

	i_free(file->full_path);
	file->full_path = fs->path_prefix == NULL ? i_strdup(file->file.path) :
		i_strconcat(fs->path_prefix, file->file.path, NULL);
}

static int fs_posix_write_finish_link(struct posix_fs_file *file)
{
	struct posix_fs *fs = (struct posix_fs *)file->file.fs;
	unsigned int try_count = 0;
	int ret;

	ret = link(file->temp_path, file->full_path);
	while (ret < 0 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT) {
		if (fs_posix_mkdir_parents(fs, file->full_path) < 0)
			return -1;
		ret = link(file->temp_path, file->full_path);
		try_count++;
	}
	if (ret < 0) {
		fs_set_error(file->file.fs, "link(%s, %s) failed: %m",
			     file->temp_path, file->full_path);
	}
	return ret;
}

static int fs_posix_write_finish(struct posix_fs_file *file)
{
	struct posix_fs *fs = (struct posix_fs *)file->file.fs;
	unsigned int try_count = 0;
	int ret, old_errno;

	if ((file->open_flags & FS_OPEN_FLAG_FSYNC) != 0 &&
	    !fs->disable_fsync) {
		if (fdatasync(file->fd) < 0) {
			fs_set_error(file->file.fs, "fdatasync(%s) failed: %m",
				     file->full_path);
			return -1;
		}
	}
	if (fs->accurate_mtime) {
		/* Linux updates the mtime timestamp only on timer interrupts.
		   This isn't anywhere close to being microsecond precision.
		   If requested, use utimes() to explicitly set a more accurate
		   mtime. */
		struct timeval tv[2];
		if (gettimeofday(&tv[0], NULL) < 0)
			i_fatal("gettimeofday() failed: %m");
		tv[1] = tv[0];
		if ((utimes(file->temp_path, tv)) < 0) {
			fs_set_error(file->file.fs, "utimes(%s) failed: %m",
				     file->temp_path);
			return -1;
		}
	}

	fs_posix_write_rename_if_needed(file);
	switch (file->open_mode) {
	case FS_OPEN_MODE_CREATE_UNIQUE_128:
	case FS_OPEN_MODE_CREATE:
		ret = fs_posix_write_finish_link(file);
		old_errno = errno;
		if (unlink(file->temp_path) < 0) {
			fs_set_error(file->file.fs, "unlink(%s) failed: %m",
				     file->temp_path);
		}
		errno = old_errno;
		if (ret < 0) {
			fs_posix_file_close(&file->file);
			i_free_and_null(file->temp_path);
			return -1;
		}
		break;
	case FS_OPEN_MODE_REPLACE:
		ret = rename(file->temp_path, file->full_path);
		while (ret < 0 && errno == ENOENT &&
		       try_count <= MAX_MKDIR_RETRY_COUNT) {
			if (fs_posix_mkdir_parents(fs, file->full_path) < 0)
				return -1;
			ret = rename(file->temp_path, file->full_path);
			try_count++;
		}
		if (ret < 0) {
			fs_set_error(file->file.fs, "rename(%s, %s) failed: %m",
				     file->temp_path, file->full_path);
			return -1;
		}
		break;
	default:
		i_unreached();
	}
	i_free_and_null(file->temp_path);
	file->seek_to_beginning = TRUE;
	/* allow opening the file after writing to it */
	file->open_mode = FS_OPEN_MODE_READONLY;
	return 0;
}

static int fs_posix_write(struct fs_file *_file, const void *data, size_t size)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	ssize_t ret;

	if (file->fd == -1) {
		if (fs_posix_open(file) < 0)
			return -1;
		i_assert(file->fd != -1);
	}

	if (file->open_mode != FS_OPEN_MODE_APPEND) {
		if (write_full(file->fd, data, size) < 0) {
			fs_set_error(_file->fs, "write(%s) failed: %m",
				     file->full_path);
			return -1;
		}
		return fs_posix_write_finish(file);
	}

	/* atomic append - it should either succeed or fail */
	ret = write(file->fd, data, size);
	if (ret < 0) {
		fs_set_error(_file->fs, "write(%s) failed: %m", file->full_path);
		return -1;
	}
	if ((size_t)ret != size) {
		fs_set_error(_file->fs,
			     "write(%s) returned %"PRIuSIZE_T"/%"PRIuSIZE_T,
			     file->full_path, (size_t)ret, size);
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
	} else if (file->fd == -1 && fs_posix_open(file) < 0) {
		_file->output = o_stream_create_error_str(errno, "%s",
			fs_file_last_error(_file));
	} else {
		i_assert(file->fd != -1);
		_file->output = o_stream_create_fd_file(file->fd,
							(uoff_t)-1, FALSE);
	}
	o_stream_set_name(_file->output, file->full_path);
}

static int fs_posix_write_stream_finish(struct fs_file *_file, bool success)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	int ret = success ? 0 : -1;

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
	case FS_OPEN_MODE_CREATE_UNIQUE_128:
	case FS_OPEN_MODE_REPLACE:
		if (ret == 0)
			ret = fs_posix_write_finish(file);
		break;
	case FS_OPEN_MODE_READONLY:
		i_unreached();
	}
	return ret < 0 ? -1 : 1;
}

static int
fs_posix_lock(struct fs_file *_file, unsigned int secs, struct fs_lock **lock_r)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	struct posix_fs *fs = (struct posix_fs *)_file->fs;
	struct dotlock_settings dotlock_set;
	struct posix_fs_lock fs_lock, *ret_lock;
	int ret = -1;

	i_zero(&fs_lock);
	fs_lock.lock.file = _file;

	switch (fs->lock_method) {
	case FS_POSIX_LOCK_METHOD_FLOCK:
#ifndef HAVE_FLOCK
		fs_set_error(_file->fs, "flock() not supported by OS "
			     "(for file %s)", file->full_path);
#else
		if (secs == 0) {
			ret = file_try_lock(file->fd, file->full_path, F_WRLCK,
					    FILE_LOCK_METHOD_FLOCK,
					    &fs_lock.file_lock);
		} else {
			ret = file_wait_lock(file->fd, file->full_path, F_WRLCK,
					     FILE_LOCK_METHOD_FLOCK, secs,
					     &fs_lock.file_lock);
		}
		if (ret < 0) {
			fs_set_error(_file->fs, "flock(%s) failed: %m",
				     file->full_path);
		}
#endif
		break;
	case FS_POSIX_LOCK_METHOD_DOTLOCK:
		i_zero(&dotlock_set);
		dotlock_set.stale_timeout = FS_POSIX_DOTLOCK_STALE_TIMEOUT_SECS;
		dotlock_set.use_excl_lock = TRUE;
		dotlock_set.timeout = secs;

		ret = file_dotlock_create(&dotlock_set, file->full_path,
					  secs == 0 ? 0 :
					  DOTLOCK_CREATE_FLAG_NONBLOCK,
					  &fs_lock.dotlock);
		if (ret < 0) {
			fs_set_error(_file->fs,
				     "file_dotlock_create(%s) failed: %m",
				     file->full_path);
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
		file_dotlock_delete(&lock->dotlock);
	i_free(lock);
}

static int fs_posix_exists(struct fs_file *_file)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	struct stat st;

	if (stat(file->full_path, &st) < 0) {
		if (errno != ENOENT) {
			fs_set_error(_file->fs, "stat(%s) failed: %m",
				     file->full_path);
			return -1;
		}
		return 0;
	}
	return 1;
}

static int fs_posix_stat(struct fs_file *_file, struct stat *st_r)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	/* in case output != NULL it means that we're still writing to the file
	   and fs_stat() shouldn't stat the unfinished file. this is done by
	   fs-sis after fs_copy(). */
	if (file->fd != -1 && _file->output == NULL) {
		if (fstat(file->fd, st_r) < 0) {
			fs_set_error(_file->fs, "fstat(%s) failed: %m", file->full_path);
			return -1;
		}
	} else {
		if (stat(file->full_path, st_r) < 0) {
			fs_set_error(_file->fs, "stat(%s) failed: %m", file->full_path);
			return -1;
		}
	}
	return 0;
}

static int fs_posix_copy(struct fs_file *_src, struct fs_file *_dest)
{
	struct posix_fs_file *src = (struct posix_fs_file *)_src;
	struct posix_fs_file *dest = (struct posix_fs_file *)_dest;
	struct posix_fs *fs = (struct posix_fs *)_src->fs;
	unsigned int try_count = 0;
	int ret;

	fs_posix_write_rename_if_needed(dest);
	ret = link(src->full_path, dest->full_path);
	if (errno == EEXIST && dest->open_mode == FS_OPEN_MODE_REPLACE) {
		/* destination file already exists - replace it */
		i_unlink_if_exists(dest->full_path);
		ret = link(src->full_path, dest->full_path);
	}
	while (ret < 0 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT) {
		if (fs_posix_mkdir_parents(fs, dest->full_path) < 0)
			return -1;
		ret = link(src->full_path, dest->full_path);
		try_count++;
	}
	if (ret < 0) {
		fs_set_error(_src->fs, "link(%s, %s) failed: %m",
			     src->full_path, dest->full_path);
		return -1;
	}
	return 0;
}

static int fs_posix_rename(struct fs_file *_src, struct fs_file *_dest)
{
	struct posix_fs *fs = (struct posix_fs *)_src->fs;
	struct posix_fs_file *src = (struct posix_fs_file *)_src;
	struct posix_fs_file *dest = (struct posix_fs_file *)_dest;
	unsigned int try_count = 0;
	int ret;

	ret = rename(src->full_path, dest->full_path);
	while (ret < 0 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT) {
		if (fs_posix_mkdir_parents(fs, dest->full_path) < 0)
			return -1;
		ret = rename(src->full_path, dest->full_path);
		try_count++;
	}
	if (ret < 0) {
		fs_set_error(_src->fs, "rename(%s, %s) failed: %m",
			     src->full_path, dest->full_path);
		return -1;
	}
	return 0;
}

static int fs_posix_delete(struct fs_file *_file)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	struct posix_fs *fs = (struct posix_fs *)_file->fs;

	if (unlink(file->full_path) < 0) {
		if (!UNLINK_EISDIR(errno)) {
			fs_set_error(_file->fs, "unlink(%s) failed: %m", file->full_path);
			return -1;
		}
		/* attempting to delete a directory. convert it to rmdir()
		   automatically. */
		if (rmdir(file->full_path) < 0) {
			fs_set_error(_file->fs, "rmdir(%s) failed: %m", file->full_path);
			return -1;
		}
	}
	(void)fs_posix_rmdir_parents(fs, file->full_path);
	return 0;
}

static struct fs_iter *fs_posix_iter_alloc(void)
{
	struct posix_fs_iter *iter = i_new(struct posix_fs_iter, 1);
	return &iter->iter;
}

static void
fs_posix_iter_init(struct fs_iter *_iter, const char *path,
		   enum fs_iter_flags flags ATTR_UNUSED)
{
	struct posix_fs_iter *iter = (struct posix_fs_iter *)_iter;
	struct posix_fs *fs = (struct posix_fs *)_iter->fs;

	iter->path = fs->path_prefix == NULL ? i_strdup(path) :
		i_strconcat(fs->path_prefix, path, NULL);
	if (iter->path[0] == '\0') {
		i_free(iter->path);
		iter->path = i_strdup(".");
	}
	iter->dir = opendir(iter->path);
	if (iter->dir == NULL && errno != ENOENT) {
		iter->err = errno;
		fs_set_error(_iter->fs, "opendir(%s) failed: %m", iter->path);
	}
}

static bool fs_posix_iter_want(struct posix_fs_iter *iter, const char *fname)
{
	bool ret;

	T_BEGIN {
		const char *path = t_strdup_printf("%s/%s", iter->path, fname);
		struct stat st;

		if (stat(path, &st) < 0 &&
		    lstat(path, &st) < 0)
			ret = FALSE;
		else if (!S_ISDIR(st.st_mode))
			ret = (iter->iter.flags & FS_ITER_FLAG_DIRS) == 0;
		else
			ret = (iter->iter.flags & FS_ITER_FLAG_DIRS) != 0;
	} T_END;
	return ret;
}

static const char *fs_posix_iter_next(struct fs_iter *_iter)
{
	struct posix_fs_iter *iter = (struct posix_fs_iter *)_iter;
	struct posix_fs *fs = (struct posix_fs *)_iter->fs;
	struct dirent *d;

	if (iter->dir == NULL)
		return NULL;

	errno = 0;
	for (; (d = readdir(iter->dir)) != NULL; errno = 0) {
		if (strcmp(d->d_name, ".") == 0 ||
		    strcmp(d->d_name, "..") == 0)
			continue;
		if (strncmp(d->d_name, fs->temp_file_prefix,
			    fs->temp_file_prefix_len) == 0)
			continue;
#ifdef HAVE_DIRENT_D_TYPE
		switch (d->d_type) {
		case DT_UNKNOWN:
			if (fs_posix_iter_want(iter, d->d_name))
				return d->d_name;
			break;
		case DT_DIR:
			if ((iter->iter.flags & FS_ITER_FLAG_DIRS) != 0)
				return d->d_name;
			break;
		default:
			if ((iter->iter.flags & FS_ITER_FLAG_DIRS) == 0)
				return d->d_name;
			break;
		}
#else
		if (fs_posix_iter_want(iter, d->d_name))
			return d->d_name;
#endif
	}
	if (errno != 0) {
		iter->err = errno;
		fs_set_error(_iter->fs, "readdir(%s) failed: %m", iter->path);
	}
	return NULL;
}

static int fs_posix_iter_deinit(struct fs_iter *_iter)
{
	struct posix_fs_iter *iter = (struct posix_fs_iter *)_iter;
	int ret = 0;

	if (iter->dir != NULL && closedir(iter->dir) < 0 && iter->err == 0) {
		iter->err = errno;
		fs_set_error(_iter->fs, "closedir(%s) failed: %m", iter->path);
	}
	if (iter->err != 0) {
		errno = iter->err;
		ret = -1;
	}
	i_free(iter->path);
	i_free(iter);
	return ret;
}

const struct fs fs_class_posix = {
	.name = "posix",
	.v = {
		fs_posix_alloc,
		fs_posix_init,
		fs_posix_deinit,
		fs_posix_get_properties,
		fs_posix_file_alloc,
		fs_posix_file_init,
		fs_posix_file_deinit,
		fs_posix_file_close,
		NULL,
		NULL, NULL,
		fs_default_set_metadata,
		NULL,
		fs_posix_prefetch,
		fs_posix_read,
		fs_posix_read_stream,
		fs_posix_write,
		fs_posix_write_stream,
		fs_posix_write_stream_finish,
		fs_posix_lock,
		fs_posix_unlock,
		fs_posix_exists,
		fs_posix_stat,
		fs_posix_copy,
		fs_posix_rename,
		fs_posix_delete,
		fs_posix_iter_alloc,
		fs_posix_iter_init,
		fs_posix_iter_next,
		fs_posix_iter_deinit,
		NULL,
		NULL,
	}
};
