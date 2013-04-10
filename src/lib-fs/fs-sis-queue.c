/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "fs-sis-common.h"

#define QUEUE_DIR_NAME "queue"

struct sis_queue_fs {
	struct fs fs;
	struct fs *super;
	char *queue_dir;
};

struct sis_queue_fs_file {
	struct fs_file file;
	struct sis_queue_fs *fs;
	struct fs_file *super;
};

static void fs_sis_queue_copy_error(struct sis_queue_fs *fs)
{
	fs_set_error(&fs->fs, "%s", fs_last_error(fs->super));
}

static void fs_sis_queue_file_copy_error(struct sis_queue_fs_file *file)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)file->file.fs;

	fs_sis_queue_copy_error(fs);
}

static struct fs *fs_sis_queue_alloc(void)
{
	struct sis_queue_fs *fs;

	fs = i_new(struct sis_queue_fs, 1);
	fs->fs = fs_class_sis_queue;
	return &fs->fs;
}

static int
fs_sis_queue_init(struct fs *_fs, const char *args,
		  const struct fs_settings *set)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;
	const char *p, *parent_name, *parent_args, *error;

	/* <queue_dir>:<parent fs>[:<args>] */

	p = strchr(args, ':');
	if (p == NULL || p[1] == '\0') {
		fs_set_error(_fs, "Parent filesystem not given as parameter");
		return -1;
	}

	fs->queue_dir = i_strdup_until(args, p);
	parent_name = p + 1;

	parent_args = strchr(parent_name, ':');
	if (parent_args == NULL)
		parent_args = "";
	else
		parent_name = t_strdup_until(parent_name, parent_args++);
	if (fs_init(parent_name, parent_args, set, &fs->super, &error) < 0) {
		fs_set_error(_fs, "%s: %s", parent_name, error);
		return -1;
	}
	return 0;
}

static void fs_sis_queue_deinit(struct fs *_fs)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	if (fs->super != NULL)
		fs_deinit(&fs->super);
	i_free(fs->queue_dir);
	i_free(fs);
}

static enum fs_properties fs_sis_queue_get_properties(struct fs *_fs)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	return fs_get_properties(fs->super);
}

static struct fs_file *
fs_sis_queue_file_init(struct fs *_fs, const char *path,
		       enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;
	struct sis_queue_fs_file *file;

	file = i_new(struct sis_queue_fs_file, 1);
	file->file.fs = _fs;
	file->file.path = i_strdup(path);
	file->fs = fs;

	if (mode == FS_OPEN_MODE_APPEND)
		fs_set_error(_fs, "APPEND mode not supported");
	else
		file->super = fs_file_init(fs->super, path, mode | flags);
	return &file->file;
}

static void fs_sis_queue_file_deinit(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (file->super != NULL)
		fs_file_deinit(&file->super);
	i_free(file->file.path);
	i_free(file);
}

static void fs_sis_queue_file_close(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (file->super != NULL)
		fs_file_close(file->super);
}

static const char *fs_sis_queue_file_get_path(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	return fs_file_path(file->super);
}

static void
fs_sis_queue_set_async_callback(struct fs_file *_file,
				fs_file_async_callback_t *callback,
				void *context)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	fs_file_set_async_callback(file->super, callback, context);
}

static int fs_sis_queue_wait_async(struct fs *_fs)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	return fs_wait_async(fs->super);
}

static void
fs_sis_queue_set_metadata(struct fs_file *_file, const char *key,
			  const char *value)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	fs_set_metadata(file->super, key, value);
}

static int
fs_sis_queue_get_metadata(struct fs_file *_file,
			  const ARRAY_TYPE(fs_metadata) **metadata_r)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	return fs_get_metadata(file->super, metadata_r);
}

static bool fs_sis_queue_prefetch(struct fs_file *_file, uoff_t length)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	return fs_prefetch(file->super, length);
}

static ssize_t fs_sis_queue_read(struct fs_file *_file, void *buf, size_t size)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;
	ssize_t ret;

	if ((ret = fs_read(file->super, buf, size)) < 0)
		fs_sis_queue_file_copy_error(file);
	return ret;
}

static struct istream *
fs_sis_queue_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	return fs_read_stream(file->super, max_buffer_size);
}

static void fs_sis_queue_add(struct sis_queue_fs_file *file)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)file->file.fs;
	struct fs_file *queue_file;
	const char *fname, *path, *queue_path;

	path = fs_file_path(&file->file);
	fname = strrchr(path, '/');
	if (fname != NULL)
		fname++;
	else
		fname = path;

	queue_path = t_strdup_printf("%s/%s", fs->queue_dir, fname);
	queue_file = fs_file_init(fs->super, queue_path, FS_OPEN_MODE_CREATE);
	if (fs_write(queue_file, "", 0) < 0 && errno != EEXIST)
		i_error("fs-sis-queue: %s", fs_last_error(fs->super));
	fs_file_deinit(&queue_file);
}

static int fs_sis_queue_write(struct fs_file *_file, const void *data, size_t size)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (file->super == NULL)
		return -1;
	if (fs_write(file->super, data, size) < 0) {
		fs_sis_queue_file_copy_error(file);
		return -1;
	}
	T_BEGIN {
		fs_sis_queue_add(file);
	} T_END;
	return 0;
}

static void fs_sis_queue_write_stream(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	i_assert(_file->output == NULL);

	if (file->super == NULL)
		_file->output = o_stream_create_error(EINVAL);
	else
		_file->output = fs_write_stream(file->super);
	o_stream_set_name(_file->output, _file->path);
}

static int fs_sis_queue_write_stream_finish(struct fs_file *_file, bool success)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (!success) {
		if (file->super != NULL) {
			fs_write_stream_abort(file->super, &_file->output);
			fs_sis_queue_file_copy_error(file);
		}
		return -1;
	}

	if (fs_write_stream_finish(file->super, &_file->output) < 0) {
		fs_sis_queue_file_copy_error(file);
		return -1;
	}
	T_BEGIN {
		fs_sis_queue_add(file);
	} T_END;
	return 1;
}

static int
fs_sis_queue_lock(struct fs_file *_file, unsigned int secs,
		  struct fs_lock **lock_r)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (fs_lock(file->super, secs, lock_r) < 0) {
		fs_sis_queue_file_copy_error(file);
		return -1;
	}
	return 0;
}

static void fs_sis_queue_unlock(struct fs_lock *_lock ATTR_UNUSED)
{
	i_unreached();
}

static int fs_sis_queue_exists(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (fs_exists(file->super) < 0) {
		fs_sis_queue_copy_error(file->fs);
		return -1;
	}
	return 0;
}

static int fs_sis_queue_stat(struct fs_file *_file, struct stat *st_r)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (fs_stat(file->super, st_r) < 0) {
		fs_sis_queue_copy_error(file->fs);
		return -1;
	}
	return 0;
}

static int fs_sis_queue_copy(struct fs_file *_src, struct fs_file *_dest)
{
	struct sis_queue_fs_file *src = (struct sis_queue_fs_file *)_src;
	struct sis_queue_fs_file *dest = (struct sis_queue_fs_file *)_dest;

	if (fs_copy(src->super, dest->super) < 0) {
		fs_sis_queue_copy_error(src->fs);
		return -1;
	}
	return 0;
}

static int
fs_sis_queue_rename(struct fs_file *_src, struct fs_file *_dest)
{
	struct sis_queue_fs_file *src = (struct sis_queue_fs_file *)_src;
	struct sis_queue_fs_file *dest = (struct sis_queue_fs_file *)_dest;

	if (fs_rename(src->super, dest->super) < 0) {
		fs_sis_queue_copy_error(src->fs);
		return -1;
	}
	return 0;
}

static int fs_sis_queue_delete(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	T_BEGIN {
		fs_sis_try_unlink_hash_file(_file->fs, file->super);
	} T_END;
	if (fs_delete(file->super) < 0) {
		fs_sis_queue_copy_error(file->fs);
		return -1;
	}
	return 0;
}

static struct fs_iter *
fs_sis_queue_iter_init(struct fs *_fs, const char *path,
		       enum fs_iter_flags flags)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	return fs_iter_init(fs->super, path, flags);
}

const struct fs fs_class_sis_queue = {
	.name = "sis-queue",
	.v = {
		fs_sis_queue_alloc,
		fs_sis_queue_init,
		fs_sis_queue_deinit,
		fs_sis_queue_get_properties,
		fs_sis_queue_file_init,
		fs_sis_queue_file_deinit,
		fs_sis_queue_file_close,
		fs_sis_queue_file_get_path,
		fs_sis_queue_set_async_callback,
		fs_sis_queue_wait_async,
		fs_sis_queue_set_metadata,
		fs_sis_queue_get_metadata,
		fs_sis_queue_prefetch,
		fs_sis_queue_read,
		fs_sis_queue_read_stream,
		fs_sis_queue_write,
		fs_sis_queue_write_stream,
		fs_sis_queue_write_stream_finish,
		fs_sis_queue_lock,
		fs_sis_queue_unlock,
		fs_sis_queue_exists,
		fs_sis_queue_stat,
		fs_sis_queue_copy,
		fs_sis_queue_rename,
		fs_sis_queue_delete,
		fs_sis_queue_iter_init,
		NULL,
		NULL
	}
};
