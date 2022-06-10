/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-tee.h"
#include "istream-try.h"
#include "ostream.h"
#include "iostream-temp.h"
#include "compression.h"
#include "fs-api-private.h"

struct compress_fs {
	struct fs fs;
	const struct compression_handler *compress_handler;
	int compress_level;
	bool try_plain;
};

struct compress_fs_file {
	struct fs_file file;
	struct compress_fs *fs;
	struct fs_file *super_read;
	enum fs_open_mode open_mode;
	struct istream *input;

	struct ostream *super_output;
	struct ostream *temp_output;
};

#define COMPRESS_FS(ptr)	container_of((ptr), struct compress_fs, fs)
#define COMPRESS_FILE(ptr)	container_of((ptr), struct compress_fs_file, file)

extern const struct fs fs_class_compress;

static struct fs *fs_compress_alloc(void)
{
	struct compress_fs *fs;

	fs = i_new(struct compress_fs, 1);
	fs->fs = fs_class_compress;
	return &fs->fs;
}

static int
fs_compress_init(struct fs *_fs, const char *args,
		 const struct fs_settings *set, const char **error_r)
{
	struct compress_fs *fs = COMPRESS_FS(_fs);
	const char *p, *compression_name, *level_str;
	const char *parent_name, *parent_args;
	int ret;

	/* get compression handler name */
	if (str_begins(args, "maybe-", &args))
		fs->try_plain = TRUE;

	p = strchr(args, ':');
	if (p == NULL) {
		*error_r = "Compression method not given as parameter";
		return -1;
	}
	compression_name = t_strdup_until(args, p++);
	args = p;

	/* get compression level */
	p = strchr(args, ':');
	if (p == NULL || p[1] == '\0') {
		*error_r = "Parent filesystem not given as parameter";
		return -1;
	}

	level_str = t_strdup_until(args, p++);
	args = p;
	ret = compression_lookup_handler(compression_name, &fs->compress_handler);
	if (ret <= 0) {
		*error_r = t_strdup_printf("Compression method '%s' %s.",
					   compression_name, ret == 0 ?
					   "not supported" : "unknown");
		return -1;
	}
	if (str_to_int(level_str, &fs->compress_level) < 0 ||
	    fs->compress_level < fs->compress_handler->get_min_level() ||
	    fs->compress_level > fs->compress_handler->get_max_level()) {
		 *error_r = t_strdup_printf(
			"Invalid compression level parameter '%s': "
			"Level must be between %d..%d", level_str,
			fs->compress_handler->get_min_level(),
			fs->compress_handler->get_max_level());
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
	return fs_init(parent_name, parent_args, set, &_fs->parent, error_r);
}

static void fs_compress_free(struct fs *_fs)
{
	struct compress_fs *fs = COMPRESS_FS(_fs);

	i_free(fs);
}

static struct fs_file *fs_compress_file_alloc(void)
{
	struct compress_fs_file *file = i_new(struct compress_fs_file, 1);
	return &file->file;
}

static void
fs_compress_file_init(struct fs_file *_file, const char *path,
		      enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct compress_fs *fs = COMPRESS_FS(_file->fs);
	struct compress_fs_file *file = COMPRESS_FILE(_file);

	file->file.path = i_strdup(path);
	file->fs = fs;
	file->open_mode = mode;

	/* avoid unnecessarily creating two seekable streams */
	flags &= ENUM_NEGATE(FS_OPEN_FLAG_SEEKABLE);

	file->file.parent = fs_file_init_parent(_file, path, mode, flags);
	if (mode == FS_OPEN_MODE_READONLY &&
	    (flags & FS_OPEN_FLAG_ASYNC) == 0) {
		/* use async stream for parent, so fs_read_stream() won't create
		   another seekable stream needlessly */
		file->super_read = fs_file_init_parent(_file, path,
			mode, flags | FS_OPEN_FLAG_ASYNC |
			FS_OPEN_FLAG_ASYNC_NOQUEUE);
	} else {
		file->super_read = file->file.parent;
	}
}

static void fs_compress_file_deinit(struct fs_file *_file)
{
	struct compress_fs_file *file = COMPRESS_FILE(_file);

	if (file->super_read != _file->parent)
		fs_file_deinit(&file->super_read);
	fs_file_free(_file);
	i_free(file->file.path);
	i_free(file);
}

static void fs_compress_file_close(struct fs_file *_file)
{
	struct compress_fs_file *file = COMPRESS_FILE(_file);

	i_stream_unref(&file->input);
	fs_file_close(file->super_read);
	fs_file_close(_file->parent);
}

static struct istream *
fs_compress_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct compress_fs_file *file = COMPRESS_FILE(_file);
	struct istream *input;
	enum istream_decompress_flags flags = 0;

	if (file->input != NULL) {
		i_stream_ref(file->input);
		i_stream_seek(file->input, 0);
		return file->input;
	}

	input = fs_read_stream(file->super_read, max_buffer_size);
	if (file->fs->try_plain)
		flags |= ISTREAM_DECOMPRESS_FLAG_TRY;
	file->input = i_stream_create_decompress(input, flags);
	i_stream_unref(&input);
	i_stream_ref(file->input);
	return file->input;
}

static void fs_compress_write_stream(struct fs_file *_file)
{
	struct compress_fs_file *file = COMPRESS_FILE(_file);

	if (file->fs->compress_level == 0) {
		fs_wrapper_write_stream(_file);
		return;
	}

	i_assert(_file->output == NULL);

	file->temp_output =
		iostream_temp_create_named(_file->fs->temp_path_prefix,
					   IOSTREAM_TEMP_FLAG_TRY_FD_DUP,
					   fs_file_path(_file));
	_file->output = file->fs->compress_handler->
		create_ostream(file->temp_output, file->fs->compress_level);
}

static int fs_compress_write_stream_finish(struct fs_file *_file, bool success)
{
	struct compress_fs_file *file = COMPRESS_FILE(_file);
	struct istream *input;
	int ret;

	if (file->fs->compress_level == 0)
		return fs_wrapper_write_stream_finish(_file, success);

	if (_file->output != NULL) {
		if (_file->output->closed)
			success = FALSE;
		if (_file->output == file->super_output)
			_file->output = NULL;
		else
			o_stream_unref(&_file->output);
	}
	if (!success) {
		o_stream_destroy(&file->temp_output);
		if (file->super_output != NULL)
			fs_write_stream_abort_parent(_file, &file->super_output);
		return -1;
	}

	if (file->super_output != NULL) {
		i_assert(file->temp_output == NULL);
		return fs_write_stream_finish(_file->parent, &file->super_output);
	}
	if (file->temp_output == NULL) {
		/* finishing up */
		i_assert(file->super_output == NULL);
		return fs_write_stream_finish(_file->parent, &file->temp_output);
	}
	/* finish writing the temporary file */
	input = iostream_temp_finish(&file->temp_output, IO_BLOCK_SIZE);
	file->super_output = fs_write_stream(_file->parent);
	o_stream_nsend_istream(file->super_output, input);
	ret = fs_write_stream_finish(_file->parent, &file->super_output);
	i_stream_unref(&input);
	return ret;
}

const struct fs fs_class_compress = {
	.name = "compress",
	.v = {
		.alloc = fs_compress_alloc,
		.init = fs_compress_init,
		.deinit = NULL,
		.free = fs_compress_free,
		.get_properties = fs_wrapper_get_properties,
		.file_alloc = fs_compress_file_alloc,
		.file_init = fs_compress_file_init,
		.file_deinit = fs_compress_file_deinit,
		.file_close = fs_compress_file_close,
		.get_path = fs_wrapper_file_get_path,
		.set_async_callback = fs_wrapper_set_async_callback,
		.wait_async = fs_wrapper_wait_async,
		.set_metadata = fs_wrapper_set_metadata,
		.get_metadata = fs_wrapper_get_metadata,
		.prefetch = fs_wrapper_prefetch,
		.read = fs_read_via_stream,
		.read_stream = fs_compress_read_stream,
		.write = fs_write_via_stream,
		.write_stream = fs_compress_write_stream,
		.write_stream_finish = fs_compress_write_stream_finish,
		.lock = fs_wrapper_lock,
		.unlock = fs_wrapper_unlock,
		.exists = fs_wrapper_exists,
		.stat = fs_wrapper_stat,
		.copy = fs_wrapper_copy,
		.rename = fs_wrapper_rename,
		.delete_file = fs_wrapper_delete,
		.iter_alloc = fs_wrapper_iter_alloc,
		.iter_init = fs_wrapper_iter_init,
		.iter_next = fs_wrapper_iter_next,
		.iter_deinit = fs_wrapper_iter_deinit,
		.switch_ioloop = NULL,
		.get_nlinks = fs_wrapper_get_nlinks
	}
};
