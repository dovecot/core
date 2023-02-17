/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-nonuls.h"
#include "ostream.h"
#include "ostream-cmp.h"
#include "fs-sis-common.h"

#define FS_SIS_REQUIRED_PROPS \
	(FS_PROPERTY_FASTCOPY | FS_PROPERTY_STAT)

struct sis_fs {
	struct fs fs;
};

struct sis_fs_file {
	struct fs_file file;
	struct sis_fs *fs;
	enum fs_open_mode open_mode;

	struct fs_file *hash_file;
	struct istream *hash_input;
	struct ostream *fs_output;

	char *hash, *hash_path;
	bool opened;
};

#define SIS_FS(ptr)	container_of((ptr), struct sis_fs, fs)
#define SIS_FILE(ptr)	container_of((ptr), struct sis_fs_file, file)

static struct fs *fs_sis_alloc(void)
{
	struct sis_fs *fs;

	fs = i_new(struct sis_fs, 1);
	fs->fs = fs_class_sis;
	return &fs->fs;
}

static int
fs_sis_init(struct fs *_fs, const char *args, const struct fs_settings *set,
	    const char **error_r)
{
	enum fs_properties props;
	const char *parent_name, *parent_args;

	if (*args == '\0') {
		*error_r = "Parent filesystem not given as parameter";
		return -1;
	}

	parent_args = strchr(args, ':');
	if (parent_args == NULL) {
		parent_name = args;
		parent_args = "";
	} else {
		parent_name = t_strdup_until(args, parent_args);
		parent_args++;
	}
	if (fs_init(parent_name, parent_args, set, &_fs->parent, error_r) < 0)
		return -1;
	props = fs_get_properties(_fs->parent);
	if ((props & FS_SIS_REQUIRED_PROPS) != FS_SIS_REQUIRED_PROPS) {
		*error_r = t_strdup_printf("%s backend can't be used with SIS",
					   parent_name);
		return -1;
	}
	return 0;
}

static void fs_sis_free(struct fs *_fs)
{
	struct sis_fs *fs = SIS_FS(_fs);

	i_free(fs);
}

static struct fs_file *fs_sis_file_alloc(void)
{
	struct sis_fs_file *file = i_new(struct sis_fs_file, 1);
	return &file->file;
}

static void
fs_sis_file_init(struct fs_file *_file, const char *path,
		 enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct sis_fs_file *file = SIS_FILE(_file);
	struct sis_fs *fs = SIS_FS(_file->fs);
	const char *dir, *hash;

	file->file.path = i_strdup(path);
	file->fs = fs;
	file->open_mode = mode;
	if (mode == FS_OPEN_MODE_APPEND) {
		fs_set_error(_file->event, ENOTSUP, "APPEND mode not supported");
		return;
	}

	if (fs_sis_path_parse(_file, path, &dir, &hash) < 0)
		return;

	/* if hashes/<hash> already exists, open it */
	file->hash_path = i_strdup_printf("%s/"HASH_DIR_NAME"/%s", dir, hash);
	file->hash_file = fs_file_init_parent(_file, file->hash_path,
					      FS_OPEN_MODE_READONLY, 0);

	file->hash_input = fs_read_stream(file->hash_file, IO_BLOCK_SIZE);
	if (i_stream_read(file->hash_input) == -1) {
		/* doesn't exist */
		if (errno != ENOENT) {
			e_error(file->file.event, "Couldn't read hash file %s: %m",
				file->hash_path);
		}
		i_stream_destroy(&file->hash_input);
	}

	file->file.parent = fs_file_init_parent(_file, path, mode, flags);
}

static void fs_sis_file_deinit(struct fs_file *_file)
{
	struct sis_fs_file *file = SIS_FILE(_file);

	fs_file_deinit(&file->hash_file);
	fs_file_free(_file);
	i_free(file->hash);
	i_free(file->hash_path);
	i_free(file->file.path);
	i_free(file);
}

static void fs_sis_file_close(struct fs_file *_file)
{
	struct sis_fs_file *file = SIS_FILE(_file);

	i_stream_unref(&file->hash_input);
	fs_file_close(file->hash_file);
	fs_file_close(_file->parent);
}

static bool fs_sis_try_link(struct sis_fs_file *file)
{
	const struct stat *st;
	struct stat st2;

	if (i_stream_stat(file->hash_input, FALSE, &st) < 0)
		return FALSE;

	/* we can use the existing file */
	if (fs_copy(file->hash_file, file->file.parent) < 0) {
		if (errno != ENOENT && errno != EMLINK) {
			e_error(file->file.event, "%s",
				fs_file_last_error(file->hash_file));
		}
		/* failed to use link(), continue as if it hadn't been equal */
		return FALSE;
	}
	if (fs_stat(file->file.parent, &st2) < 0) {
		e_error(file->file.event, "%s",
			fs_file_last_error(file->file.parent));
		if (fs_delete(file->file.parent) < 0) {
			e_error(file->file.event, "%s",
				fs_file_last_error(file->file.parent));
		}
		return FALSE;
	}
	if (st->st_ino != st2.st_ino) {
		/* the hashes/ file was already replaced with something else */
		if (fs_delete(file->file.parent) < 0) {
			e_error(file->file.event, "%s",
				fs_file_last_error(file->file.parent));
		}
		return FALSE;
	}
	return TRUE;
}

static struct istream *
fs_sis_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct istream *result = fs_read_stream(_file->parent, max_buffer_size);
	if (result->stream_errno == ENOENT) {
		const char *file_size_str;
		uoff_t file_size;
		if (fs_lookup_metadata(_file, FS_METADATA_FILE_SIZE, &file_size_str) <= 0)
			return result;
		if (str_to_uoff(file_size_str, &file_size) < 0)
			return result;
		i_stream_unref(&result);
		e_warning(_file->event, "File %s is missing, replacing with spaces", _file->path);
		struct istream *zeroes_stream = i_stream_create_file("/dev/zero", max_buffer_size);
		struct istream *space_stream = i_stream_create_nonuls(zeroes_stream, ' ');
		result = i_stream_create_limit(space_stream, file_size);
		i_stream_unref(&space_stream);
		i_stream_unref(&zeroes_stream);
	}
	return result;
}

static int fs_sis_write(struct fs_file *_file, const void *data, size_t size)
{
	struct sis_fs_file *file = SIS_FILE(_file);

	if (_file->parent == NULL)
		return -1;

	if (file->hash_input != NULL &&
	    stream_cmp_block(file->hash_input, data, size) &&
	    i_stream_read_eof(file->hash_input)) {
		/* try to use existing file */
		if (fs_sis_try_link(file))
			return 0;
	}

	if (fs_write(_file->parent, data, size) < 0)
		return -1;
	return 0;
}

static void fs_sis_write_stream(struct fs_file *_file)
{
	if (_file->parent == NULL) {
		_file->output = o_stream_create_error_str(EINVAL, "%s",
						fs_file_last_error(_file));
	} else {
		_file->output = fs_write_stream(_file->parent);
	}
	o_stream_set_name(_file->output, _file->path);
}

static int fs_sis_write_stream_finish(struct fs_file *_file, bool success)
{

	if (!success) {
		if (_file->parent != NULL)
			fs_write_stream_abort_parent(_file, &_file->output);
		return -1;
	}


	return fs_write_stream_finish(_file->parent, &_file->output);
}

static int fs_sis_delete(struct fs_file *_file)
{
	return fs_delete(_file->parent);
}

const struct fs fs_class_sis = {
	.name = "sis",
	.v = {
		.alloc = fs_sis_alloc,
		.init = fs_sis_init,
		.deinit = NULL,
		.free = fs_sis_free,
		.get_properties = fs_wrapper_get_properties,
		.file_alloc = fs_sis_file_alloc,
		.file_init = fs_sis_file_init,
		.file_deinit = fs_sis_file_deinit,
		.file_close = fs_sis_file_close,
		.get_path = fs_wrapper_file_get_path,
		.set_async_callback = fs_wrapper_set_async_callback,
		.wait_async = fs_wrapper_wait_async,
		.set_metadata = fs_wrapper_set_metadata,
		.get_metadata = fs_wrapper_get_metadata,
		.prefetch = fs_wrapper_prefetch,
		.read = fs_wrapper_read,
		.read_stream = fs_sis_read_stream,
		.write = fs_sis_write,
		.write_stream = fs_sis_write_stream,
		.write_stream_finish = fs_sis_write_stream_finish,
		.lock = fs_wrapper_lock,
		.unlock = fs_wrapper_unlock,
		.exists = fs_wrapper_exists,
		.stat = fs_wrapper_stat,
		.copy = fs_wrapper_copy,
		.rename = fs_wrapper_rename,
		.delete_file = fs_sis_delete,
		.iter_alloc = fs_wrapper_iter_alloc,
		.iter_init = fs_wrapper_iter_init,
		.iter_next = NULL,
		.iter_deinit = NULL,
		.switch_ioloop = NULL,
		.get_nlinks = fs_wrapper_get_nlinks,
	}
};
