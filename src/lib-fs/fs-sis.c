/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
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
	struct sis_fs *fs = (struct sis_fs *)_fs;

	fs_deinit(&_fs->parent);
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
	struct sis_fs_file *file = (struct sis_fs_file *)_file;
	struct sis_fs *fs = (struct sis_fs *)_file->fs;
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
					      FS_OPEN_MODE_READONLY);

	file->hash_input = fs_read_stream(file->hash_file, IO_BLOCK_SIZE);
	if (i_stream_read(file->hash_input) == -1) {
		/* doesn't exist */
		if (errno != ENOENT) {
			e_error(file->file.event, "Couldn't read hash file %s: %m",
				file->hash_path);
		}
		i_stream_destroy(&file->hash_input);
	}

	file->file.parent = fs_file_init_parent(_file, path, mode | flags);
}

static void fs_sis_file_deinit(struct fs_file *_file)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	fs_file_deinit(&file->hash_file);
	fs_file_free(_file);
	i_free(file->hash);
	i_free(file->hash_path);
	i_free(file->file.path);
	i_free(file);
}

static void fs_sis_file_close(struct fs_file *_file)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

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

static void fs_sis_replace_hash_file(struct sis_fs_file *file)
{
	struct fs *super_fs = file->file.parent->fs;
	struct fs_file *temp_file;
	const char *hash_fname;
	string_t *temp_path;
	int ret;

	if (file->hash_input == NULL) {
		/* hash file didn't exist previously. we should be able to
		   create it with link() */
		if (fs_copy(file->file.parent, file->hash_file) < 0) {
			if (errno == EEXIST) {
				/* the file was just created. it's probably
				   a duplicate, but it's too much trouble
				   trying to deduplicate it anymore */
			} else {
				e_error(file->file.event, "%s",
					fs_file_last_error(file->hash_file));
			}
		}
		return;
	}

	temp_path = t_str_new(256);
	hash_fname = strrchr(file->hash_path, '/');
	if (hash_fname == NULL)
		hash_fname = file->hash_path;
	else {
		str_append_data(temp_path, file->hash_path,
				(hash_fname-file->hash_path) + 1);
		hash_fname++;
	}
	str_printfa(temp_path, "%s%s.tmp",
		    super_fs->set.temp_file_prefix, hash_fname);

	/* replace existing hash file atomically */
	temp_file = fs_file_init_parent(&file->file, str_c(temp_path),
					FS_OPEN_MODE_READONLY);
	ret = fs_copy(file->file.parent, temp_file);
	if (ret < 0 && errno == EEXIST) {
		/* either someone's racing us or it's a stale file.
		   try to continue. */
		if (fs_delete(temp_file) < 0 &&
		    errno != ENOENT)
			e_error(file->file.event, "%s", fs_file_last_error(temp_file));
		ret = fs_copy(file->file.parent, temp_file);
	}
	if (ret < 0) {
		e_error(file->file.event, "%s", fs_file_last_error(temp_file));
		fs_file_deinit(&temp_file);
		return;
	}

	if (fs_rename(temp_file, file->hash_file) < 0) {
		if (errno == ENOENT) {
			/* apparently someone else just renamed it. ignore. */
		} else {
			e_error(file->file.event, "%s",
				fs_file_last_error(file->hash_file));
		}
		(void)fs_delete(temp_file);
	}
	fs_file_deinit(&temp_file);
}

static int fs_sis_write(struct fs_file *_file, const void *data, size_t size)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

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
	T_BEGIN {
		fs_sis_replace_hash_file(file);
	} T_END;
	return 0;
}

static void fs_sis_write_stream(struct fs_file *_file)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	i_assert(_file->output == NULL);

	if (_file->parent == NULL) {
		_file->output = o_stream_create_error_str(EINVAL, "%s",
						fs_file_last_error(_file));
	} else {
		file->fs_output = fs_write_stream(_file->parent);
		if (file->hash_input == NULL) {
			_file->output = file->fs_output;
			o_stream_ref(_file->output);
		} else {
			/* compare if files are equal */
			_file->output = o_stream_create_cmp(file->fs_output,
							    file->hash_input);
		}
	}
	o_stream_set_name(_file->output, _file->path);
}

static int fs_sis_write_stream_finish(struct fs_file *_file, bool success)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	if (!success) {
		if (_file->parent != NULL)
			fs_write_stream_abort_parent(_file, &file->fs_output);
		o_stream_unref(&_file->output);
		return -1;
	}

	if (file->hash_input != NULL &&
	    o_stream_cmp_equals(_file->output) &&
	    i_stream_read_eof(file->hash_input)) {
		o_stream_unref(&_file->output);
		if (fs_sis_try_link(file)) {
			fs_write_stream_abort_parent(_file, &file->fs_output);
			return 1;
		}
	}
	if (_file->output != NULL)
		o_stream_unref(&_file->output);

	if (fs_write_stream_finish(_file->parent, &file->fs_output) < 0)
		return -1;
	T_BEGIN {
		fs_sis_replace_hash_file(file);
	} T_END;
	return 1;
}

static int fs_sis_delete(struct fs_file *_file)
{
	T_BEGIN {
		fs_sis_try_unlink_hash_file(_file, _file->parent);
	} T_END;
	return fs_delete(_file->parent);
}

const struct fs fs_class_sis = {
	.name = "sis",
	.v = {
		fs_sis_alloc,
		fs_sis_init,
		NULL,
		fs_sis_free,
		fs_wrapper_get_properties,
		fs_sis_file_alloc,
		fs_sis_file_init,
		fs_sis_file_deinit,
		fs_sis_file_close,
		fs_wrapper_file_get_path,
		fs_wrapper_set_async_callback,
		fs_wrapper_wait_async,
		fs_wrapper_set_metadata,
		fs_wrapper_get_metadata,
		fs_wrapper_prefetch,
		fs_wrapper_read,
		fs_wrapper_read_stream,
		fs_sis_write,
		fs_sis_write_stream,
		fs_sis_write_stream_finish,
		fs_wrapper_lock,
		fs_wrapper_unlock,
		fs_wrapper_exists,
		fs_wrapper_stat,
		fs_wrapper_copy,
		fs_wrapper_rename,
		fs_sis_delete,
		fs_wrapper_iter_alloc,
		fs_wrapper_iter_init,
		NULL,
		NULL,
		NULL,
		fs_wrapper_get_nlinks,
	}
};
