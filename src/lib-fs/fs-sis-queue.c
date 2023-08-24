/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "settings.h"
#include "fs-sis-common.h"

struct fs_sis_queue_settings {
	pool_t pool;
	const char *fs_sis_queue_path;
};

struct sis_queue_fs {
	struct fs fs;
	char *queue_dir;
};

struct sis_queue_fs_file {
	struct fs_file file;
	struct sis_queue_fs *fs;
};

#define SISQUEUE_FS(ptr)	container_of((ptr), struct sis_queue_fs, fs)
#define SISQUEUE_FILE(ptr)	container_of((ptr), struct sis_queue_fs_file, file)

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct fs_sis_queue_settings)
static const struct setting_define fs_sis_queue_setting_defines[] = {
	DEF(STR, fs_sis_queue_path),

	SETTING_DEFINE_LIST_END
};
static const struct fs_sis_queue_settings fs_sis_queue_default_settings = {
	.fs_sis_queue_path = "",
};

const struct setting_parser_info fs_sis_queue_setting_parser_info = {
	.name = "fs_sis_queue",

	.defines = fs_sis_queue_setting_defines,
	.defaults = &fs_sis_queue_default_settings,

	.struct_size = sizeof(struct fs_sis_queue_settings),
	.pool_offset1 = 1 + offsetof(struct fs_sis_queue_settings, pool),
};

static struct fs *fs_sis_queue_alloc(void)
{
	struct sis_queue_fs *fs;

	fs = i_new(struct sis_queue_fs, 1);
	fs->fs = fs_class_sis_queue;
	return &fs->fs;
}

static int
fs_sis_queue_init(struct fs *_fs, const struct fs_parameters *params,
		  const char **error_r)
{
	struct sis_queue_fs *fs = SISQUEUE_FS(_fs);
	const struct fs_sis_queue_settings *set;

	if (settings_get(_fs->event, &fs_sis_queue_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;
	fs->queue_dir = i_strdup(set->fs_sis_queue_path);
	settings_free(set);

	return fs_init_parent(_fs, params, error_r);
}

static void fs_sis_queue_free(struct fs *_fs)
{
	struct sis_queue_fs *fs = SISQUEUE_FS(_fs);

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
	struct sis_queue_fs_file *file = SISQUEUE_FILE(_file);
	struct sis_queue_fs *fs = SISQUEUE_FS(_file->fs);

	file->file.path = i_strdup(path);
	file->fs = fs;

	if (mode == FS_OPEN_MODE_APPEND)
		fs_set_error(_file->event, ENOTSUP, "APPEND mode not supported");
	else
		file->file.parent = fs_file_init_parent(_file, path, mode, flags);
}

static void fs_sis_queue_file_deinit(struct fs_file *_file)
{
	struct sis_queue_fs_file *file = SISQUEUE_FILE(_file);

	fs_file_free(_file);
	i_free(file->file.path);
	i_free(file);
}

static void fs_sis_queue_add(struct sis_queue_fs_file *file)
{
	struct sis_queue_fs *fs = SISQUEUE_FS(file->file.fs);
	struct fs_file *queue_file;
	const char *fname, *path, *queue_path;

	path = fs_file_path(&file->file);
	fname = strrchr(path, '/');
	if (fname != NULL)
		fname++;
	else
		fname = path;

	queue_path = t_strdup_printf("%s/%s", fs->queue_dir, fname);
	queue_file = fs_file_init_parent(&file->file, queue_path, FS_OPEN_MODE_CREATE, 0);
	if (fs_write(queue_file, "", 0) < 0 && errno != EEXIST)
		e_error(file->file.event, "%s", fs_file_last_error(queue_file));
	fs_file_deinit(&queue_file);
}

static int fs_sis_queue_write(struct fs_file *_file, const void *data, size_t size)
{
	struct sis_queue_fs_file *file = SISQUEUE_FILE(_file);

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
	struct sis_queue_fs_file *file = SISQUEUE_FILE(_file);

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
		.alloc = fs_sis_queue_alloc,
		.init = fs_sis_queue_init,
		.deinit = NULL,
		.free = fs_sis_queue_free,
		.get_properties = fs_wrapper_get_properties,
		.file_alloc = fs_sis_queue_file_alloc,
		.file_init = fs_sis_queue_file_init,
		.file_deinit = fs_sis_queue_file_deinit,
		.file_close = fs_wrapper_file_close,
		.get_path = fs_wrapper_file_get_path,
		.set_async_callback = fs_wrapper_set_async_callback,
		.wait_async = fs_wrapper_wait_async,
		.set_metadata = fs_wrapper_set_metadata,
		.get_metadata = fs_wrapper_get_metadata,
		.prefetch = fs_wrapper_prefetch,
		.read = fs_wrapper_read,
		.read_stream = fs_wrapper_read_stream,
		.write = fs_sis_queue_write,
		.write_stream = fs_sis_queue_write_stream,
		.write_stream_finish = fs_sis_queue_write_stream_finish,
		.lock = fs_wrapper_lock,
		.unlock = fs_wrapper_unlock,
		.exists = fs_wrapper_exists,
		.stat = fs_wrapper_stat,
		.copy = fs_wrapper_copy,
		.rename = fs_wrapper_rename,
		.delete_file = fs_sis_queue_delete,
		.iter_alloc = fs_wrapper_iter_alloc,
		.iter_init = fs_wrapper_iter_init,
		.iter_next = NULL,
		.iter_deinit = NULL,
		.switch_ioloop = NULL,
		.get_nlinks = fs_wrapper_get_nlinks,
	}
};
