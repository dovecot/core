/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "fs-sis-common.h"

#define QUEUE_DIR_NAME "queue"

struct sis_queue_fs {
	struct fs fs;
	struct fs *super;
	char *queue_dir;
};

struct sis_queue_fs_file {
	struct fs_file file;
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

static struct fs *
fs_sis_queue_init(const char *args, const struct fs_settings *set)
{
	struct sis_queue_fs *fs;
	const char *p, *parent_fs;

	fs = i_new(struct sis_queue_fs, 1);
	fs->fs = fs_class_sis_queue;

	/* <queue_dir>:<parent fs>[:<args>] */

	p = strchr(args, ':');
	if (p == NULL || p[1] == '\0')
		i_fatal("fs-sis-queue: Parent filesystem not given as parameter");

	fs->queue_dir = i_strdup_until(args, p);
	parent_fs = p + 1;

	p = strchr(parent_fs, ':');
	if (p == NULL)
		fs->super = fs_init(parent_fs, "", set);
	else
		fs->super = fs_init(t_strdup_until(parent_fs, p), p+1, set);
	return &fs->fs;
}

static void fs_sis_queue_deinit(struct fs *_fs)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	fs_deinit(&fs->super);
	i_free(fs->queue_dir);
	i_free(fs);
}

static int
fs_sis_queue_open(struct fs *_fs, const char *path, enum fs_open_mode mode,
		  enum fs_open_flags flags, struct fs_file **file_r)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;
	struct sis_queue_fs_file *file;
	struct fs_file *super;

	if (mode == FS_OPEN_MODE_APPEND) {
		fs_set_error(_fs, "APPEND mode not supported");
		return -1;
	}

	if (fs_open(fs->super, path, mode | flags, &super) < 0) {
		fs_sis_queue_copy_error(fs);
		return -1;
	}

	switch (mode) {
	case FS_OPEN_MODE_RDONLY:
		*file_r = super;
		return 0;
	case FS_OPEN_MODE_CREATE:
	case FS_OPEN_MODE_REPLACE:
		break;
	case FS_OPEN_MODE_APPEND:
		i_unreached();
	}

	file = i_new(struct sis_queue_fs_file, 1);
	file->file.fs = _fs;
	file->file.path = i_strdup(fs_file_path(super));
	file->super = super;
	*file_r = &file->file;
	return 0;
}

static void fs_sis_queue_close(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	fs_close(&file->super);
	i_free(file->file.path);
	i_free(file);
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
	if (fs_open(fs->super, queue_path,
		    FS_OPEN_MODE_CREATE | FS_OPEN_FLAG_MKDIR,
		    &queue_file) < 0) {
		i_error("fs-sis-queue: %s", fs_last_error(fs->super));
		return;
	}
	if (fs_write(queue_file, "", 0) < 0 && errno != EEXIST)
		i_error("fs-sis-queue: %s", fs_last_error(fs->super));
	fs_close(&queue_file);
}

static int fs_sis_queue_write(struct fs_file *_file, const void *data, size_t size)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

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

	_file->output = fs_write_stream(file->super);
}

static int fs_sis_queue_write_stream_finish(struct fs_file *_file, bool success)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (!success) {
		fs_write_stream_abort(file->super, &_file->output);
		fs_sis_queue_file_copy_error(file);
		return -1;
	}

	if (fs_write_stream_finish(file->super, &_file->output) < 0) {
		fs_sis_queue_file_copy_error(file);
		return -1;
	}
	T_BEGIN {
		fs_sis_queue_add(file);
	} T_END;
	return 0;
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

static int fs_sis_queue_fdatasync(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = (struct sis_queue_fs_file *)_file;

	if (fs_fdatasync(file->super) < 0) {
		fs_sis_queue_file_copy_error(file);
		return -1;
	}
	return 0;
}

static int fs_sis_queue_exists(struct fs *_fs, const char *path)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	if (fs_exists(fs->super, path) < 0) {
		fs_sis_queue_copy_error(fs);
		return -1;
	}
	return 0;
}

static int fs_sis_queue_stat(struct fs *_fs, const char *path,
			     struct stat *st_r)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	if (fs_stat(fs->super, path, st_r) < 0) {
		fs_sis_queue_copy_error(fs);
		return -1;
	}
	return 0;
}

static int fs_sis_queue_link(struct fs *_fs, const char *src, const char *dest)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	if (fs_link(fs->super, src, dest) < 0) {
		fs_sis_queue_copy_error(fs);
		return -1;
	}
	return 0;
}

static int
fs_sis_queue_rename(struct fs *_fs, const char *src, const char *dest)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	if (fs_rename(fs->super, src, dest) < 0) {
		fs_sis_queue_copy_error(fs);
		return -1;
	}
	return 0;
}

static int fs_sis_queue_unlink(struct fs *_fs, const char *path)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	T_BEGIN {
		fs_sis_try_unlink_hash_file(&fs->fs, fs->super, path);
	} T_END;
	if (fs_unlink(fs->super, path) < 0) {
		fs_sis_queue_copy_error(fs);
		return -1;
	}
	return 0;
}

static int fs_sis_queue_rmdir(struct fs *_fs, const char *path)
{
	struct sis_queue_fs *fs = (struct sis_queue_fs *)_fs;

	if (fs_rmdir(fs->super, path) < 0) {
		fs_sis_queue_copy_error(fs);
		return -1;
	}
	return 0;
}

struct fs fs_class_sis_queue = {
	.name = "sis-queue",
	.v = {
		fs_sis_queue_init,
		fs_sis_queue_deinit,
		fs_sis_queue_open,
		fs_sis_queue_close,
		fs_sis_queue_read,
		fs_sis_queue_read_stream,
		fs_sis_queue_write,
		fs_sis_queue_write_stream,
		fs_sis_queue_write_stream_finish,
		fs_sis_queue_lock,
		fs_sis_queue_unlock,
		fs_sis_queue_fdatasync,
		fs_sis_queue_exists,
		fs_sis_queue_stat,
		fs_sis_queue_link,
		fs_sis_queue_rename,
		fs_sis_queue_unlink,
		fs_sis_queue_rmdir
	}
};
