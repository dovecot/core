/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "fs-sis-common.h"

#define QUEUE_DIR_NAME "queue"

struct sis_queue_fs {
	struct fs fs;
	char *queue_dir;
};

struct sis_queue_fs_file {
	struct fs_file file;
	struct sis_queue_fs *fs;
};

static struct fs *fs_sis_queue_alloc(void)
{
	struct sis_queue_fs *fs;

	fs = i_new(struct sis_queue_fs, 1);
	fs->fs = fs_class_sis_queue;
	return &fs->fs;
}

static int
fs_sis_queue_init(struct fs *_fs, const char *args,
		  const struct fs_settings *set, const char **error_r)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;
	const char *p, *parent_name, *parent_args;

	/* <queue_dir>:<parent fs>[:<args>] */

	p = strchr(args, ':');
	if (p == NULL || p[1] == '\0') {
		*error_r = "Parent filesystem not given as parameter";
		return -1;
	}

	fs->queue_dir = i_strdup_until(args, p);
	parent_name = p + 1;

	parent_args = strchr(parent_name, ':');
	if (parent_args == NULL)
		parent_args = "";
	else
		parent_name = t_strdup_until(parent_name, parent_args++);
	if (fs_init(parent_name, parent_args, set, &_fs->parent, error_r) < 0)
		return -1;
	return 0;
}

static void fs_sis_queue_deinit(struct fs *_fs)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	fs_deinit(&_fs->parent);
	i_free(fs->queue_dir);
	i_free(fs);
}

static struct fs_file *fs_sis_queue_file_alloc(void)
{
	struct sis_queue_fs_file *file = i_new(struct sis_queue_fs_file, 1);
	return &file->file;
}

static void
fs_sis_queue_file_init(struct fs_file *_file, const char *path,
		       enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_file->fs;

	file->file.path = i_strdup(path);
	file->fs = fs;

	if (mode == FS_OPEN_MODE_APPEND)
		fs_set_error(_file->event, "APPEND mode not supported");
	else
		file->file.parent = fs_file_init_parent(_file, path, mode | flags);
}

static void fs_sis_queue_file_deinit(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	fs_file_deinit(&_file->parent);
	i_free(file->file.path);
	i_free(file);
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
	queue_file = fs_file_init_parent(&file->file, queue_path, FS_OPEN_MODE_CREATE);
	if (fs_write(queue_file, "", 0) < 0 && errno != EEXIST)
		e_error(file->file.event, "%s", fs_file_last_error(queue_file));
	fs_file_deinit(&queue_file);
}

static int fs_sis_queue_write(struct fs_file *_file, const void *data, size_t size)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (_file->parent == NULL)
		return -1;
	if (fs_write(_file->parent, data, size) < 0)
		return -1;
	T_BEGIN {
		fs_sis_queue_add(file);
	} T_END;
	return 0;
}

static void fs_sis_queue_write_stream(struct fs_file *_file)
{
	i_assert(_file->output == NULL);

	if (_file->parent == NULL) {
		_file->output = o_stream_create_error_str(EINVAL, "%s",
						fs_file_last_error(_file));
	} else {
		_file->output = fs_write_stream(_file->parent);
	}
	o_stream_set_name(_file->output, _file->path);
}

static int fs_sis_queue_write_stream_finish(struct fs_file *_file, bool success)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (!success) {
		if (_file->parent != NULL)
			fs_write_stream_abort_parent(_file, &_file->output);
		return -1;
	}

	if (fs_write_stream_finish(_file->parent, &_file->output) < 0)
		return -1;
	T_BEGIN {
		fs_sis_queue_add(file);
	} T_END;
	return 1;
}

static int fs_sis_queue_delete(struct fs_file *_file)
{
	T_BEGIN {
		fs_sis_try_unlink_hash_file(_file, _file->parent);
	} T_END;
	return fs_delete(_file->parent);
}

const struct fs fs_class_sis_queue = {
	.name = "sis-queue",
	.v = {
		fs_sis_queue_alloc,
		fs_sis_queue_init,
		fs_sis_queue_deinit,
		fs_wrapper_get_properties,
		fs_sis_queue_file_alloc,
		fs_sis_queue_file_init,
		fs_sis_queue_file_deinit,
		fs_wrapper_file_close,
		fs_wrapper_file_get_path,
		fs_wrapper_set_async_callback,
		fs_wrapper_wait_async,
		fs_wrapper_set_metadata,
		fs_wrapper_get_metadata,
		fs_wrapper_prefetch,
		fs_wrapper_read,
		fs_wrapper_read_stream,
		fs_sis_queue_write,
		fs_sis_queue_write_stream,
		fs_sis_queue_write_stream_finish,
		fs_wrapper_lock,
		fs_wrapper_unlock,
		fs_wrapper_exists,
		fs_wrapper_stat,
		fs_wrapper_copy,
		fs_wrapper_rename,
		fs_sis_queue_delete,
		fs_wrapper_iter_alloc,
		fs_wrapper_iter_init,
		NULL,
		NULL,
		NULL,
		fs_wrapper_get_nlinks,
	}
};
