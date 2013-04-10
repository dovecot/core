/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

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
#include <stdlib.h>
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
	char *temp_file_prefix, *root_path;
	enum fs_posix_lock_method lock_method;
	mode_t mode, dir_mode;
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
	fs->root_path = i_strdup(set->root_path);
	fs->fs.set.temp_file_prefix = fs->temp_file_prefix;
	fs->fs.set.root_path = fs->root_path;

	fs->lock_method = FS_POSIX_LOCK_METHOD_FLOCK;
	fs->mode = FS_DEFAULT_MODE;

	tmp = t_strsplit_spaces(args, " ");
	for (; *tmp != NULL; tmp++) {
		const char *arg = *tmp;

		if (strcmp(arg, "lock=flock") == 0)
			fs->lock_method = FS_POSIX_LOCK_METHOD_FLOCK;
		else if (strcmp(arg, "lock=dotlock") == 0)
			fs->lock_method = FS_POSIX_LOCK_METHOD_DOTLOCK;
		else if (strncmp(arg, "mode=", 5) == 0) {
			fs->mode = strtoul(arg+5, NULL, 8) & 0666;
			if (fs->mode == 0) {
				fs_set_error(_fs, "Invalid mode: %s", arg+5);
				return -1;
			}
		} else {
			fs_set_error(_fs, "Unknown arg '%s'", arg);
			return -1;
		}
	}
	fs->dir_mode = fs->mode;
	if ((fs->dir_mode & 0600) != 0) fs->dir_mode |= 0100;
	if ((fs->dir_mode & 0060) != 0) fs->dir_mode |= 0010;
	if ((fs->dir_mode & 0006) != 0) fs->dir_mode |= 0001;
	return 0;
}

static void fs_posix_deinit(struct fs *_fs)
{
	struct posix_fs *fs = (struct posix_fs *)_fs;

	i_free(fs->temp_file_prefix);
	i_free(fs->root_path);
	i_free(fs);
}

static enum fs_properties fs_posix_get_properties(struct fs *fs ATTR_UNUSED)
{
	return FS_PROPERTY_LOCKS | FS_PROPERTY_FASTCOPY | FS_PROPERTY_RENAME |
		FS_PROPERTY_STAT | FS_PROPERTY_ITER | FS_PROPERTY_RELIABLEITER;
}

static int fs_posix_mkdir_parents(struct posix_fs *fs, const char *path)
{
	const char *dir, *fname;

	fname = strrchr(path, '/');
	if (fname == NULL)
		return 1;
	dir = t_strdup_until(path, fname);
	if (mkdir_parents(dir, fs->dir_mode) == 0)
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

	if (fs->root_path == NULL)
		return 0;

	while ((p = strrchr(path, '/')) != NULL) {
		path = t_strdup_until(path, p);
		if (strcmp(path, fs->root_path) == 0)
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
	int fd;

	i_assert(file->temp_path == NULL);

	if (file->open_mode == FS_OPEN_MODE_CREATE_UNIQUE_128) {
		str_append(str, file->file.path);
		str_append_c(str, '/');
	} else if ((slash = strrchr(file->file.path, '/')) != NULL) {
		str_append_n(str, file->file.path, slash - file->file.path + 1);
	}
	str_append(str, fs->temp_file_prefix);

	fd = safe_mkstemp_hostpid(str, fs->mode, (uid_t)-1, (gid_t)-1);
	while (fd == -1 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT) {
		if (fs_posix_mkdir_parents(fs, str_c(str)) < 0)
			return -1;
		fd = safe_mkstemp_hostpid(str, fs->mode, (uid_t)-1, (gid_t)-1);
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
	const char *path = file->file.path;

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

static struct fs_file *
fs_posix_file_init(struct fs *_fs, const char *path,
		   enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct posix_fs_file *file;

	file = i_new(struct posix_fs_file, 1);
	file->file.fs = _fs;
	file->file.path = i_strdup(path);
	file->open_mode = mode;
	file->open_flags = flags;
	file->fd = -1;
	return &file->file;
}

static void fs_posix_file_close(struct fs_file *_file)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	if (file->fd != -1 && file->file.output == NULL) {
		if (close(file->fd) < 0) {
			fs_set_critical(file->file.fs, "close(%s) failed: %m",
					file->file.path);
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
		if (file->success || file->temp_path == NULL)
			break;
		/* failed to create/replace this. delete the temp file */
		if (unlink(file->temp_path) < 0) {
			fs_set_critical(_file->fs, "unlink(%s) failed: %m",
					file->temp_path);
		}
		break;
	}

	i_free(file->temp_path);
	i_free(file->file.path);
	i_free(file);
}

static bool fs_posix_prefetch(struct fs_file *_file, uoff_t length ATTR_UNUSED)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;

	if (file->fd == -1) {
		if (fs_posix_open(file) < 0)
			return TRUE;
	}

/* HAVE_POSIX_FADVISE alone isn't enough for CentOS 4.9 */
#if defined(HAVE_POSIX_FADVISE) && defined(POSIX_FADV_WILLNEED)
	if (posix_fadvise(file->fd, 0, length, POSIX_FADV_WILLNEED) < 0) {
		i_error("posix_fadvise(%s) failed: %m", _file->path);
		return TRUE;
	}
#endif
	return FALSE;
}

static ssize_t fs_posix_read(struct fs_file *_file, void *buf, size_t size)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	ssize_t ret;

	if (file->fd == -1) {
		if (fs_posix_open(file) < 0)
			return -1;
	}

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
	fs_posix_file_close(_file);
	return ret;
}

static struct istream *
fs_posix_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	struct istream *input;

	if (file->fd == -1 && fs_posix_open(file) < 0) {
		input = i_stream_create_error(errno);
		i_stream_set_name(input, _file->path);
	} else {
		input = i_stream_create_fd(file->fd, max_buffer_size, FALSE);
	}
	i_stream_add_destroy_callback(input, fs_posix_file_close, _file);
	return input;
}

static int fs_posix_write_finish(struct posix_fs_file *file)
{
	int ret;

	if ((file->open_flags & FS_OPEN_FLAG_FSYNC) != 0) {
		if (fdatasync(file->fd) < 0) {
			fs_set_error(file->file.fs, "fdatasync(%s) failed: %m",
				     file->file.path);
			return -1;
		}
	}

	if (close(file->fd) < 0) {
		file->fd = -1;
		fs_set_error(file->file.fs, "close(%s) failed: %m",
			     file->file.path);
		return -1;
	}
	file->fd = -1;

	switch (file->open_mode) {
	case FS_OPEN_MODE_CREATE_UNIQUE_128:
		T_BEGIN {
			guid_128_t guid;
			char *path;

			guid_128_generate(guid);
			path = i_strdup_printf("%s/%s", file->file.path,
					       guid_128_to_string(guid));
			i_free(file->file.path);
			file->file.path = path;
		} T_END;
		/* fall through */
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
	i_free_and_null(file->temp_path);
	file->success = TRUE;
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
	}

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
	} else if (file->fd == -1 && fs_posix_open(file) < 0) {
		_file->output = o_stream_create_error(errno);
	} else {
		_file->output = o_stream_create_fd_file(file->fd,
							(uoff_t)-1, FALSE);
	}
	o_stream_set_name(_file->output, _file->path);
}

static int fs_posix_write_stream_finish(struct fs_file *_file, bool success)
{
	struct posix_fs_file *file = (struct posix_fs_file *)_file;
	int ret = success ? 0 : -1;

	if (o_stream_nfinish(_file->output) < 0) {
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
		file_dotlock_delete(&lock->dotlock);
	i_free(lock);
}

static int fs_posix_exists(struct fs_file *_file)
{
	struct stat st;

	if (stat(_file->path, &st) < 0) {
		if (errno != ENOENT) {
			fs_set_error(_file->fs, "stat(%s) failed: %m",
				     _file->path);
			return -1;
		}
		return 0;
	}
	return 1;
}

static int fs_posix_stat(struct fs_file *_file, struct stat *st_r)
{
	if (stat(_file->path, st_r) < 0) {
		fs_set_error(_file->fs, "stat(%s) failed: %m", _file->path);
		return -1;
	}
	return 0;
}

static int fs_posix_copy(struct fs_file *_src, struct fs_file *_dest)
{
	struct posix_fs *fs = (struct posix_fs *)_src->fs;
	unsigned int try_count = 0;
	int ret;

	ret = link(_src->path, _dest->path);
	while (ret < 0 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT) {
		if (fs_posix_mkdir_parents(fs, _dest->path) < 0)
			return -1;
		ret = link(_src->path, _dest->path);
		try_count++;
	}
	if (ret < 0) {
		fs_set_error(_src->fs, "link(%s, %s) failed: %m",
			     _src->path, _dest->path);
		return -1;
	}
	return 0;
}

static int fs_posix_rename(struct fs_file *_src, struct fs_file *_dest)
{
	struct posix_fs *fs = (struct posix_fs *)_src->fs;
	unsigned int try_count = 0;
	int ret;

	ret = rename(_src->path, _dest->path);
	while (ret < 0 && errno == ENOENT &&
	       try_count <= MAX_MKDIR_RETRY_COUNT) {
		if (fs_posix_mkdir_parents(fs, _dest->path) < 0)
			return -1;
		ret = rename(_src->path, _dest->path);
		try_count++;
	}
	if (ret < 0) {
		fs_set_error(_src->fs, "rename(%s, %s) failed: %m",
			     _src->path, _dest->path);
		return -1;
	}
	return 0;
}

static int fs_posix_delete(struct fs_file *_file)
{
	struct posix_fs *fs = (struct posix_fs *)_file->fs;

	if (unlink(_file->path) < 0) {
		fs_set_error(_file->fs, "unlink(%s) failed: %m", _file->path);
		return -1;
	}
	(void)fs_posix_rmdir_parents(fs, _file->path);
	return 0;
}

static struct fs_iter *
fs_posix_iter_init(struct fs *fs, const char *path, enum fs_iter_flags flags)
{
	struct posix_fs_iter *iter;

	iter = i_new(struct posix_fs_iter, 1);
	iter->iter.fs = fs;
	iter->iter.flags = flags;
	iter->path = i_strdup(path);
	iter->dir = opendir(path);
	if (iter->dir == NULL && errno != ENOENT) {
		iter->err = errno;
		fs_set_error(fs, "opendir(%s) failed: %m", path);
	}
	return &iter->iter;
}

static bool fs_posix_iter_want(struct posix_fs_iter *iter, const char *fname)
{
	bool ret;

	T_BEGIN {
		const char *path = t_strdup_printf("%s/%s", iter->path, fname);
		struct stat st;

		if (stat(path, &st) < 0)
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
	struct dirent *d;

	if (iter->dir == NULL)
		return NULL;

	errno = 0;
	for (; (d = readdir(iter->dir)) != NULL; errno = 0) {
		if (strcmp(d->d_name, ".") == 0 ||
		    strcmp(d->d_name, "..") == 0)
			continue;
#ifdef HAVE_DIRENT_D_TYPE
		switch (d->d_type) {
		case DT_UNKNOWN:
			if (!fs_posix_iter_want(iter, d->d_name))
				break;
			/* fall through */
		case DT_REG:
		case DT_LNK:
			if ((iter->iter.flags & FS_ITER_FLAG_DIRS) == 0)
				return d->d_name;
			break;
		case DT_DIR:
			if ((iter->iter.flags & FS_ITER_FLAG_DIRS) != 0)
				return d->d_name;
			break;
		default:
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
		fs_posix_file_init,
		fs_posix_file_deinit,
		fs_posix_file_close,
		NULL,
		NULL, NULL,
		NULL, NULL,
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
		fs_posix_iter_init,
		fs_posix_iter_next,
		fs_posix_iter_deinit
	}
};
