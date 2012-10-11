/* Copyright (c) 2010-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "fs-api-private.h"

static struct fs *fs_classes[] = {
	&fs_class_posix,
	&fs_class_sis,
	&fs_class_sis_queue
};

static int
fs_alloc(const struct fs *fs_class, const char *args,
	 const struct fs_settings *set, struct fs **fs_r, const char **error_r)
{
	struct fs *fs;
	int ret;

	fs = fs_class->v.alloc();
	fs->last_error = str_new(default_pool, 64);

	T_BEGIN {
		ret = fs_class->v.init(fs, args, set);
	} T_END;
	if (ret < 0) {
		/* a bit kludgy way to allow data stack frame usage in normal
		   conditions but still be able to return error message from
		   data stack. */
		*error_r = t_strdup_printf("%s: %s", fs_class->name,
					   fs_last_error(fs));
		fs_deinit(&fs);
		return -1;
	}
	*fs_r = fs;
	return 0;
}

int fs_init(const char *driver, const char *args,
	    const struct fs_settings *set,
	    struct fs **fs_r, const char **error_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(fs_classes); i++) {
		if (strcmp(fs_classes[i]->name, driver) == 0) {
			return fs_alloc(fs_classes[i], args,
					set, fs_r, error_r);
		}
	}
	*error_r = t_strdup_printf("Unknown fs driver: %s", driver);
	return -1;
}

void fs_deinit(struct fs **_fs)
{
	struct fs *fs = *_fs;
	string_t *last_error = fs->last_error;

	*_fs = NULL;

	if (fs->files_open_count > 0) {
		i_panic("fs-%s: %u files still open",
			fs->name, fs->files_open_count);
	}

	fs->v.deinit(fs);
	str_free(&last_error);
}

struct fs_file *fs_file_init(struct fs *fs, const char *path, int mode_flags)
{
	struct fs_file *file;

	i_assert(path != NULL);

	T_BEGIN {
		file = fs->v.file_init(fs, path, mode_flags & FS_OPEN_MODE_MASK,
				       mode_flags & ~FS_OPEN_MODE_MASK);
	} T_END;
	fs->files_open_count++;
	return file;
}

void fs_file_deinit(struct fs_file **_file)
{
	struct fs_file *file = *_file;

	i_assert(file->fs->files_open_count > 0);

	*_file = NULL;

	file->fs->files_open_count--;
	file->fs->v.file_deinit(file);
}

enum fs_properties fs_get_properties(struct fs *fs)
{
	return fs->v.get_properties(fs);
}

void fs_set_metadata(struct fs_file *file, const char *key, const char *value)
{
	if (file->fs->v.set_metadata != NULL)
		file->fs->v.set_metadata(file, key, value);
}

int fs_get_metadata(struct fs_file *file,
		    const ARRAY_TYPE(fs_metadata) **metadata_r)
{
	if (file->fs->v.get_metadata == NULL) {
		fs_set_error(file->fs, "Metadata not supported by backend");
		return -1;
	}
	return file->fs->v.get_metadata(file, metadata_r);
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

bool fs_prefetch(struct fs_file *file, uoff_t length)
{
	return file->fs->v.prefetch(file, length);
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

void fs_file_set_async_callback(struct fs_file *file,
				fs_file_async_callback_t *callback,
				void *context)
{
	if (file->fs->v.set_async_callback != NULL)
		file->fs->v.set_async_callback(file, callback, context);
	else
		callback(context);
}

void fs_wait_async(struct fs *fs)
{
	if (fs->v.wait_async != NULL)
		fs->v.wait_async(fs);
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

int fs_exists(struct fs_file *file)
{
	return file->fs->v.exists(file);
}

int fs_stat(struct fs_file *file, struct stat *st_r)
{
	return file->fs->v.stat(file, st_r);
}

int fs_copy(struct fs_file *src, struct fs_file *dest)
{
	i_assert(src->fs == dest->fs);
	return src->fs->v.copy(src, dest);
}

int fs_rename(struct fs_file *src, struct fs_file *dest)
{
	i_assert(src->fs == dest->fs);
	return src->fs->v.rename(src, dest);
}

int fs_delete(struct fs_file *file)
{
	return file->fs->v.delete_file(file);
}

struct fs_iter *fs_iter_init(struct fs *fs, const char *path)
{
	return fs->v.iter_init(fs, path);
}

int fs_iter_deinit(struct fs_iter **_iter)
{
	struct fs_iter *iter = *_iter;

	*_iter = NULL;
	return iter->fs->v.iter_deinit(iter);
}

const char *fs_iter_next(struct fs_iter *iter)
{
	return iter->fs->v.iter_next(iter);
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

void fs_set_error_async(struct fs *fs)
{
	fs_set_error(fs, "Asynchronous operation in progress");
	errno = EAGAIN;
}
