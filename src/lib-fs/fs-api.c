/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "fs-api-private.h"

static struct fs *fs_classes[] = {
	&fs_class_posix,
	&fs_class_sis,
	&fs_class_sis_queue
};

static struct fs *
fs_alloc(const struct fs *fs_class, const char *args,
	 const struct fs_settings *set)
{
	struct fs *fs;

	fs = fs_class->v.init(args, set);
	fs->last_error = str_new(default_pool, 64);
	return fs;
}

struct fs *fs_init(const char *driver, const char *args,
		   const struct fs_settings *set)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(fs_classes); i++) {
		if (strcmp(fs_classes[i]->name, driver) == 0)
			return fs_alloc(fs_classes[i], args, set);
	}
	i_fatal("Unknown fs driver: %s", driver);
}

void fs_deinit(struct fs **_fs)
{
	struct fs *fs = *_fs;

	*_fs = NULL;

	if (fs->files_open_count > 0) {
		i_panic("fs-%s: %u files still open",
			fs->name, fs->files_open_count);
	}

	str_free(&fs->last_error);
	fs->v.deinit(fs);
}

int fs_open(struct fs *fs, const char *path, int mode_flags,
	    struct fs_file **file_r)
{
	int ret;

	T_BEGIN {
		ret = fs->v.open(fs, path, mode_flags & FS_OPEN_MODE_MASK,
				 mode_flags & ~FS_OPEN_MODE_MASK, file_r);
	} T_END;
	if (ret == 0)
		fs->files_open_count++;
	return ret;
}

void fs_close(struct fs_file **_file)
{
	struct fs_file *file = *_file;

	i_assert(file->fs->files_open_count > 0);

	*_file = NULL;

	file->fs->files_open_count--;
	file->fs->v.close(file);
}

const char *fs_file_path(struct fs_file *file)
{
	return file->path;
}

const char *fs_last_error(struct fs *fs)
{
	if (str_len(fs->last_error) == 0)
		return "BUG: Unknown fs error";
	return str_c(fs->last_error);
}

const char *fs_file_last_error(struct fs_file *file)
{
	return fs_last_error(file->fs);
}

ssize_t fs_read(struct fs_file *file, void *buf, size_t size)
{
	return file->fs->v.read(file, buf, size);
}

struct istream *fs_read_stream(struct fs_file *file, size_t max_buffer_size)
{
	return file->fs->v.read_stream(file, max_buffer_size);
}

int fs_write(struct fs_file *file, const void *data, size_t size)
{
	return file->fs->v.write(file, data, size);
}

struct ostream *fs_write_stream(struct fs_file *file)
{
	file->fs->v.write_stream(file);
	i_assert(file->output != NULL);
	return file->output;
}

int fs_write_stream_finish(struct fs_file *file, struct ostream **output)
{
	i_assert(*output == file->output);

	*output = NULL;
	return file->fs->v.write_stream_finish(file, TRUE);
}

void fs_write_stream_abort(struct fs_file *file, struct ostream **output)
{
	i_assert(*output == file->output);

	*output = NULL;
	(void)file->fs->v.write_stream_finish(file, FALSE);
}

int fs_lock(struct fs_file *file, unsigned int secs, struct fs_lock **lock_r)
{
	return file->fs->v.lock(file, secs, lock_r);
}

void fs_unlock(struct fs_lock **_lock)
{
	struct fs_lock *lock = *_lock;

	*_lock = NULL;
	lock->file->fs->v.unlock(lock);
}

int fs_fdatasync(struct fs_file *file)
{
	return file->fs->v.fdatasync(file);
}

int fs_exists(struct fs *fs, const char *path)
{
	return fs->v.exists(fs, path);
}

int fs_stat(struct fs *fs, const char *path, struct stat *st_r)
{
	return fs->v.stat(fs, path, st_r);
}

int fs_link(struct fs *fs, const char *src, const char *dest)
{
	return fs->v.link(fs, src, dest);
}

int fs_rename(struct fs *fs, const char *src, const char *dest)
{
	return fs->v.rename(fs, src, dest);
}

int fs_unlink(struct fs *fs, const char *path)
{
	return fs->v.unlink(fs, path);
}

int fs_rmdir(struct fs *fs, const char *path)
{
	return fs->v.rmdir(fs, path);
}

void fs_set_error(struct fs *fs, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	str_truncate(fs->last_error, 0);
	str_vprintfa(fs->last_error, fmt, args);
	va_end(args);
}

void fs_set_critical(struct fs *fs, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	str_truncate(fs->last_error, 0);
	str_vprintfa(fs->last_error, fmt, args);
	i_error("fs-%s: %s", fs->name, str_c(fs->last_error));
	va_end(args);
}
