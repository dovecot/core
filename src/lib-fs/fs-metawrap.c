/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "istream.h"
#include "istream-private.h"
#include "istream-metawrap.h"
#include "ostream.h"
#include "ostream-metawrap.h"
#include "fs-api-private.h"

#define MAX_METADATA_LINE_LEN 8192

struct metawrap_fs {
	struct fs fs;
	struct fs *super;
	bool wrap_metadata;
};

struct metawrap_fs_file {
	struct fs_file file;
	struct metawrap_fs *fs;
	struct fs_file *super, *super_read;
	enum fs_open_mode open_mode;
	struct istream *input;
	struct ostream *super_output;
	bool metadata_read;
};

static void fs_metawrap_copy_error(struct metawrap_fs *fs)
{
	fs_set_error(&fs->fs, "%s", fs_last_error(fs->super));
}

static void fs_metawrap_file_copy_error(struct metawrap_fs_file *file)
{
	struct metawrap_fs *fs = (struct metawrap_fs *)file->file.fs;

	fs_metawrap_copy_error(fs);
}

static struct fs *fs_metawrap_alloc(void)
{
	struct metawrap_fs *fs;

	fs = i_new(struct metawrap_fs, 1);
	fs->fs = fs_class_metawrap;
	return &fs->fs;
}

static int
fs_metawrap_init(struct fs *_fs, const char *args, const
		 struct fs_settings *set)
{
	struct metawrap_fs *fs = (struct metawrap_fs *)_fs;
	const char *parent_name, *parent_args, *error;

	if (*args == '\0') {
		fs_set_error(_fs, "Parent filesystem not given as parameter");
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
	if (fs_init(parent_name, parent_args, set, &fs->super, &error) < 0) {
		fs_set_error(_fs, "%s: %s", parent_name, error);
		return -1;
	}
	if ((fs_get_properties(fs->super) & FS_PROPERTY_METADATA) == 0)
		fs->wrap_metadata = TRUE;
	return 0;
}

static void fs_metawrap_deinit(struct fs *_fs)
{
	struct metawrap_fs *fs = (struct metawrap_fs *)_fs;

	if (fs->super != NULL)
		fs_deinit(&fs->super);
	i_free(fs);
}

static enum fs_properties fs_metawrap_get_properties(struct fs *_fs)
{
	const struct metawrap_fs *fs = (const struct metawrap_fs *)_fs;
	enum fs_properties props;

	props = fs_get_properties(fs->super);
	if (fs->wrap_metadata) {
		/* we don't have a quick stat() to see the file's size,
		   because of the metadata header */
		props &= ~FS_PROPERTY_STAT;
	}
	return props;
}

static struct fs_file *
fs_metawrap_file_init(struct fs *_fs, const char *path,
		      enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct metawrap_fs *fs = (struct metawrap_fs *)_fs;
	struct metawrap_fs_file *file;

	file = i_new(struct metawrap_fs_file, 1);
	file->file.fs = _fs;
	file->file.path = i_strdup(path);
	file->fs = fs;
	file->open_mode = mode;

	/* avoid unnecessarily creating two seekable streams */
	flags &= ~FS_OPEN_FLAG_SEEKABLE;

	file->super = fs_file_init(fs->super, path, mode | flags);
	if (file->fs->wrap_metadata && mode == FS_OPEN_MODE_READONLY &&
	    (flags & FS_OPEN_FLAG_ASYNC) == 0) {
		/* use async stream for super, so fs_read_stream() won't create
		   another seekable stream unneededly */
		file->super_read = fs_file_init(fs->super, path, mode | flags |
						FS_OPEN_FLAG_ASYNC);
	} else {
		file->super_read = file->super;
	}
	fs_metadata_init(&file->file);
	return &file->file;
}

static void fs_metawrap_file_deinit(struct fs_file *_file)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (file->input != NULL)
		i_stream_unref(&file->input);
	if (file->super_read != file->super)
		fs_file_deinit(&file->super_read);
	fs_file_deinit(&file->super);
	i_free(file->file.path);
	i_free(file);
}

static const char *fs_metawrap_file_get_path(struct fs_file *_file)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	return fs_file_path(file->super);
}

static void
fs_metawrap_set_async_callback(struct fs_file *_file,
			       fs_file_async_callback_t *callback,
			       void *context)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	fs_file_set_async_callback(file->super, callback, context);
}

static int fs_metawrap_wait_async(struct fs *_fs)
{
	struct metawrap_fs *fs = (struct metawrap_fs *)_fs;

	if (fs_wait_async(fs->super) < 0) {
		fs_metawrap_copy_error(fs);
		return -1;
	}
	return 0;
}

static void
fs_metawrap_set_metadata(struct fs_file *_file, const char *key,
			 const char *value)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (!file->fs->wrap_metadata)
		fs_set_metadata(file->super, key, value);
	else
		fs_default_set_metadata(_file, key, value);
}

static int
fs_metawrap_get_metadata(struct fs_file *_file,
			 const ARRAY_TYPE(fs_metadata) **metadata_r)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;
	char c;

	if (!file->fs->wrap_metadata) {
		if (fs_get_metadata(file->super, metadata_r) < 0) {
			fs_metawrap_file_copy_error(file);
			return -1;
		}
		return 0;
	}

	if (!file->metadata_read) {
		if (fs_read(_file, &c, 1) < 0)
			return -1;
	}
	*metadata_r = &_file->metadata;
	return 0;
}

static bool fs_metawrap_prefetch(struct fs_file *_file, uoff_t length)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (!file->fs->wrap_metadata)
		return fs_prefetch(file->super, length);
	else
		return fs_prefetch(file->super_read, length);
}

static ssize_t fs_metawrap_read(struct fs_file *_file, void *buf, size_t size)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;
	ssize_t ret;

	if (!file->fs->wrap_metadata) {
		if ((ret = fs_read(file->super, buf, size)) < 0)
			fs_metawrap_file_copy_error(file);
		return ret;
	}
	return fs_read_via_stream(_file, buf, size);
}

static void
fs_metawrap_callback(const char *key, const char *value, void *context)
{
	struct metawrap_fs_file *file = context;

	if (key == NULL) {
		file->metadata_read = TRUE;
		return;
	}

	T_BEGIN {
		key = str_tabunescape(t_strdup_noconst(key));
		value = str_tabunescape(t_strdup_noconst(value));
		fs_default_set_metadata(&file->file, key, value);
	} T_END;
}

static struct istream *
fs_metawrap_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;
	struct istream *input;

	if (!file->fs->wrap_metadata)
		return fs_read_stream(file->super, max_buffer_size);

	if (file->input != NULL) {
		i_stream_ref(file->input);
		i_stream_seek(file->input, 0);
		return file->input;
	}

	input = fs_read_stream(file->super_read,
			       I_MAX(max_buffer_size, MAX_METADATA_LINE_LEN));
	file->input = i_stream_create_metawrap(input, fs_metawrap_callback, file);
	i_stream_unref(&input);
	i_stream_ref(file->input);
	return file->input;
}

static int fs_metawrap_write(struct fs_file *_file, const void *data, size_t size)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (!file->fs->wrap_metadata) {
		if (fs_write(file->super, data, size) < 0) {
			fs_metawrap_file_copy_error(file);
			return -1;
		}
		return 0;
	}
	return fs_write_via_stream(_file, data, size);
}

static void fs_metawrap_write_metadata(void *context)
{
	struct metawrap_fs_file *file = context;
	const struct fs_metadata *metadata;
	string_t *str = t_str_new(256);
	ssize_t ret;

	/* FIXME: if fs_set_metadata() is called later the changes are
	   ignored. we'd need to write via temporary file then. */
	array_foreach(&file->file.metadata, metadata) {
		str_append_tabescaped(str, metadata->key);
		str_append_c(str, ':');
		str_append_tabescaped(str, metadata->value);
		str_append_c(str, '\n');
	}
	str_append_c(str, '\n');
	ret = o_stream_send(file->file.output, str_data(str), str_len(str));
	if (ret < 0)
		o_stream_close(file->file.output);
	else
		i_assert((size_t)ret == str_len(str));
}

static void fs_metawrap_write_stream(struct fs_file *_file)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	i_assert(_file->output == NULL);

	file->super_output = fs_write_stream(file->super);
	if (!file->fs->wrap_metadata)
		_file->output = file->super_output;
	else {
		_file->output = o_stream_create_metawrap(file->super_output,
			fs_metawrap_write_metadata, file);
	}
}

static int fs_metawrap_write_stream_finish(struct fs_file *_file, bool success)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;
	int ret;

	if (_file->output != NULL) {
		if (_file->output->closed)
			success = FALSE;
		if (_file->output == file->super_output)
			_file->output = NULL;
		else
			o_stream_unref(&_file->output);
	}

	if (!success) {
		fs_write_stream_abort(file->super, &file->super_output);
		ret = -1;
	} else {
		ret = fs_write_stream_finish(file->super, &file->super_output);
	}

	if (ret < 0)
		fs_metawrap_file_copy_error(file);
	return ret;
}

static int
fs_metawrap_lock(struct fs_file *_file, unsigned int secs, struct fs_lock **lock_r)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (fs_lock(file->super, secs, lock_r) < 0) {
		fs_metawrap_file_copy_error(file);
		return -1;
	}
	return 0;
}

static void fs_metawrap_unlock(struct fs_lock *_lock ATTR_UNUSED)
{
	i_unreached();
}

static int fs_metawrap_exists(struct fs_file *_file)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (fs_exists(file->super) < 0) {
		fs_metawrap_copy_error(file->fs);
		return -1;
	}
	return 0;
}

static int fs_metawrap_stat(struct fs_file *_file, struct stat *st_r)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;
	struct istream *input;
	uoff_t input_size;
	ssize_t ret;

	if (!file->fs->wrap_metadata) {
		if (fs_stat(file->super, st_r) < 0) {
			fs_metawrap_copy_error(file->fs);
			return -1;
		}
		return 0;
	}
	input = fs_read_stream(_file, IO_BLOCK_SIZE);
	if ((ret = i_stream_get_size(input, TRUE, &input_size)) < 0) {
		fs_set_error(_file->fs, "i_stream_get_size(%s) failed: %m",
			     fs_file_path(_file));
		i_stream_unref(&input);
		return -1;
	}
	i_stream_unref(&input);
	if (ret == 0) {
		fs_set_error_async(_file->fs);
		return -1;
	}

	if (fs_stat(file->super, st_r) < 0) {
		i_assert(errno != EAGAIN); /* read should have caught this */
		fs_metawrap_copy_error(file->fs);
		return -1;
	}
	st_r->st_size = input_size;
	return 0;
}

static int fs_metawrap_copy(struct fs_file *_src, struct fs_file *_dest)
{
	struct metawrap_fs_file *src = (struct metawrap_fs_file *)_src;
	struct metawrap_fs_file *dest = (struct metawrap_fs_file *)_dest;

	if (!dest->fs->wrap_metadata) {
		if (fs_copy(src->super, dest->super) < 0) {
			fs_metawrap_copy_error(src->fs);
			return -1;
		}
		return 0;
	}
	return fs_default_copy(_src, _dest);
}

static int fs_metawrap_rename(struct fs_file *_src, struct fs_file *_dest)
{
	struct metawrap_fs_file *src = (struct metawrap_fs_file *)_src;
	struct metawrap_fs_file *dest = (struct metawrap_fs_file *)_dest;

	if (fs_rename(src->super, dest->super) < 0) {
		fs_metawrap_copy_error(src->fs);
		return -1;
	}
	return 0;
}

static int fs_metawrap_delete(struct fs_file *_file)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (fs_delete(file->super) < 0) {
		fs_metawrap_copy_error(file->fs);
		return -1;
	}
	return 0;
}

static struct fs_iter *
fs_metawrap_iter_init(struct fs *_fs, const char *path,
			  enum fs_iter_flags flags)
{
	struct metawrap_fs *fs = (struct metawrap_fs *)_fs;

	return fs_iter_init(fs->super, path, flags);
}

const struct fs fs_class_metawrap = {
	.name = "metawrap",
	.v = {
		fs_metawrap_alloc,
		fs_metawrap_init,
		fs_metawrap_deinit,
		fs_metawrap_get_properties,
		fs_metawrap_file_init,
		fs_metawrap_file_deinit,
		fs_metawrap_file_get_path,
		fs_metawrap_set_async_callback,
		fs_metawrap_wait_async,
		fs_metawrap_set_metadata,
		fs_metawrap_get_metadata,
		fs_metawrap_prefetch,
		fs_metawrap_read,
		fs_metawrap_read_stream,
		fs_metawrap_write,
		fs_metawrap_write_stream,
		fs_metawrap_write_stream_finish,
		fs_metawrap_lock,
		fs_metawrap_unlock,
		fs_metawrap_exists,
		fs_metawrap_stat,
		fs_metawrap_copy,
		fs_metawrap_rename,
		fs_metawrap_delete,
		fs_metawrap_iter_init,
		NULL,
		NULL
	}
};
