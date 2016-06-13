/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-temp.h"
#include "compression.h"
#include "fs-api-private.h"

struct compress_fs {
	struct fs fs;
	const struct compression_handler *handler;
	unsigned int compress_level;
};

struct compress_fs_file {
	struct fs_file file;
	struct compress_fs *fs;
	struct fs_file *super, *super_read;
	enum fs_open_mode open_mode;
	struct istream *input;

	struct ostream *super_output;
	struct ostream *temp_output;
};

struct compress_fs_iter {
	struct fs_iter iter;
	struct fs_iter *super;
};

extern const struct fs fs_class_compress;

static struct fs *fs_compress_alloc(void)
{
	struct compress_fs *fs;

	fs = i_new(struct compress_fs, 1);
	fs->fs = fs_class_compress;
	return &fs->fs;
}

static int
fs_compress_init(struct fs *_fs, const char *args, const
		 struct fs_settings *set)
{
	struct compress_fs *fs = (struct compress_fs *)_fs;
	const char *p, *compression_name, *level_str, *error;
	const char *parent_name, *parent_args;

	/* get compression handler name */
	p = strchr(args, ':');
	if (p == NULL) {
		fs_set_error(_fs, "Compression method not given as parameter");
		return -1;
	}
	compression_name = t_strdup_until(args, p++);
	args = p;

	/* get compression level */
	p = strchr(args, ':');
	if (p == NULL || p[1] == '\0') {
		fs_set_error(_fs, "Parent filesystem not given as parameter");
		return -1;
	}

	level_str = t_strdup_until(args, p++);
	if (str_to_uint(level_str, &fs->compress_level) < 0 ||
	    fs->compress_level < 1 || fs->compress_level > 9) {
		fs_set_error(_fs, "Invalid compression level parameter '%s'", level_str);
		return -1;
	}
	args = p;

	fs->handler = compression_lookup_handler(compression_name);
	if (fs->handler == NULL) {
		fs_set_error(_fs, "Compression method '%s' not support", compression_name);
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
	if (fs_init(parent_name, parent_args, set, &_fs->parent, &error) < 0) {
		fs_set_error(_fs, "%s: %s", parent_name, error);
		return -1;
	}
	return 0;
}

static void fs_compress_deinit(struct fs *_fs)
{
	struct compress_fs *fs = (struct compress_fs *)_fs;

	if (_fs->parent != NULL)
		fs_deinit(&_fs->parent);
	i_free(fs);
}

static enum fs_properties fs_compress_get_properties(struct fs *_fs)
{
	return fs_get_properties(_fs->parent);
}

static struct fs_file *
fs_compress_file_init(struct fs *_fs, const char *path,
		      enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct compress_fs *fs = (struct compress_fs *)_fs;
	struct compress_fs_file *file;

	file = i_new(struct compress_fs_file, 1);
	file->file.fs = _fs;
	file->file.path = i_strdup(path);
	file->fs = fs;
	file->open_mode = mode;

	/* avoid unnecessarily creating two seekable streams */
	flags &= ~FS_OPEN_FLAG_SEEKABLE;

	file->super = fs_file_init(_fs->parent, path, mode | flags);
	if (mode == FS_OPEN_MODE_READONLY &&
	    (flags & FS_OPEN_FLAG_ASYNC) == 0) {
		/* use async stream for super, so fs_read_stream() won't create
		   another seekable stream unneededly */
		file->super_read = fs_file_init(_fs->parent, path, mode | flags |
						FS_OPEN_FLAG_ASYNC);
	} else {
		file->super_read = file->super;
	}
	return &file->file;
}

static void fs_compress_file_deinit(struct fs_file *_file)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	if (file->super_read != file->super && file->super_read != NULL)
		fs_file_deinit(&file->super_read);
	fs_file_deinit(&file->super);
	i_free(file->file.path);
	i_free(file);
}

static void fs_compress_file_close(struct fs_file *_file)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	if (file->input != NULL)
		i_stream_unref(&file->input);
	if (file->super_read != NULL)
		fs_file_close(file->super_read);
	if (file->super != NULL)
		fs_file_close(file->super);
}

static const char *fs_compress_file_get_path(struct fs_file *_file)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	return fs_file_path(file->super);
}

static void
fs_compress_set_async_callback(struct fs_file *_file,
			       fs_file_async_callback_t *callback,
			       void *context)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	fs_file_set_async_callback(file->super, callback, context);
}

static void fs_compress_wait_async(struct fs *_fs)
{
	fs_wait_async(_fs->parent);
}

static void
fs_compress_set_metadata(struct fs_file *_file, const char *key,
			 const char *value)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	fs_set_metadata(file->super, key, value);
}

static int
fs_compress_get_metadata(struct fs_file *_file,
			 const ARRAY_TYPE(fs_metadata) **metadata_r)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	return fs_get_metadata(file->super, metadata_r);
}

static bool fs_compress_prefetch(struct fs_file *_file, uoff_t length)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	return fs_prefetch(file->super, length);
}

static struct istream *
fs_compress_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;
	struct istream *input;

	if (file->input != NULL) {
		i_stream_ref(file->input);
		i_stream_seek(file->input, 0);
		return file->input;
	}

	input = fs_read_stream(file->super_read, max_buffer_size);
	file->input = file->fs->handler->create_istream(input, FALSE);
	i_stream_unref(&input);
	i_stream_ref(file->input);
	return file->input;
}

static void fs_compress_write_stream(struct fs_file *_file)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	i_assert(_file->output == NULL);

	file->temp_output =
		iostream_temp_create_named(_file->fs->temp_path_prefix,
					   IOSTREAM_TEMP_FLAG_TRY_FD_DUP,
					   fs_file_path(_file));
	_file->output = file->fs->handler->
		create_ostream(file->temp_output, file->fs->compress_level);
}

static int fs_compress_write_stream_finish(struct fs_file *_file, bool success)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;
	struct istream *input;
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
		if (file->temp_output != NULL)
			o_stream_destroy(&file->temp_output);
		if (file->super_output != NULL)
			fs_write_stream_abort(file->super, &file->super_output);
		return -1;
	}

	if (file->super_output != NULL) {
		i_assert(file->temp_output == NULL);
		return fs_write_stream_finish(file->super, &file->super_output);
	}
	if (file->temp_output == NULL) {
		/* finishing up */
		i_assert(file->super_output == NULL);
		return fs_write_stream_finish(file->super, &file->temp_output);
	}
	/* finish writing the temporary file */
	input = iostream_temp_finish(&file->temp_output, IO_BLOCK_SIZE);
	file->super_output = fs_write_stream(file->super);
	o_stream_nsend_istream(file->super_output, input);
	ret = fs_write_stream_finish(file->super, &file->super_output);
	i_stream_unref(&input);
	return ret;
}

static int
fs_compress_lock(struct fs_file *_file, unsigned int secs, struct fs_lock **lock_r)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	return fs_lock(file->super, secs, lock_r);
}

static void fs_compress_unlock(struct fs_lock *_lock ATTR_UNUSED)
{
	i_unreached();
}

static int fs_compress_exists(struct fs_file *_file)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	return fs_exists(file->super);
}

static int fs_compress_stat(struct fs_file *_file, struct stat *st_r)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	return fs_stat(file->super, st_r);
}

static int fs_compress_copy(struct fs_file *_src, struct fs_file *_dest)
{
	struct compress_fs_file *src = (struct compress_fs_file *)_src;
	struct compress_fs_file *dest = (struct compress_fs_file *)_dest;

	if (_src != NULL)
		return fs_copy(src->super, dest->super);
	else
		return fs_copy_finish_async(dest->super);
}

static int fs_compress_rename(struct fs_file *_src, struct fs_file *_dest)
{
	struct compress_fs_file *src = (struct compress_fs_file *)_src;
	struct compress_fs_file *dest = (struct compress_fs_file *)_dest;

	return fs_rename(src->super, dest->super);
}

static int fs_compress_delete(struct fs_file *_file)
{
	struct compress_fs_file *file = (struct compress_fs_file *)_file;

	return fs_delete(file->super);
}

static struct fs_iter *
fs_compress_iter_init(struct fs *_fs, const char *path,
		      enum fs_iter_flags flags)
{
	struct compress_fs_iter *iter;

	iter = i_new(struct compress_fs_iter, 1);
	iter->iter.fs = _fs;
	iter->iter.flags = flags;
	iter->super = fs_iter_init(_fs->parent, path, flags);
	return &iter->iter;
}

static const char *fs_compress_iter_next(struct fs_iter *_iter)
{
	struct compress_fs_iter *iter = (struct compress_fs_iter *)_iter;
	const char *fname;

	iter->super->async_callback = _iter->async_callback;
	iter->super->async_context = _iter->async_context;

	fname = fs_iter_next(iter->super);
	_iter->async_have_more = iter->super->async_have_more;
	return fname;
}

static int fs_compress_iter_deinit(struct fs_iter *_iter)
{
	struct compress_fs_iter *iter = (struct compress_fs_iter *)_iter;
	int ret;

	ret = fs_iter_deinit(&iter->super);
	i_free(iter);
	return ret;
}

const struct fs fs_class_compress = {
	.name = "compress",
	.v = {
		fs_compress_alloc,
		fs_compress_init,
		fs_compress_deinit,
		fs_compress_get_properties,
		fs_compress_file_init,
		fs_compress_file_deinit,
		fs_compress_file_close,
		fs_compress_file_get_path,
		fs_compress_set_async_callback,
		fs_compress_wait_async,
		fs_compress_set_metadata,
		fs_compress_get_metadata,
		fs_compress_prefetch,
		fs_read_via_stream,
		fs_compress_read_stream,
		fs_write_via_stream,
		fs_compress_write_stream,
		fs_compress_write_stream_finish,
		fs_compress_lock,
		fs_compress_unlock,
		fs_compress_exists,
		fs_compress_stat,
		fs_compress_copy,
		fs_compress_rename,
		fs_compress_delete,
		fs_compress_iter_init,
		fs_compress_iter_next,
		fs_compress_iter_deinit,
		NULL
	}
};
