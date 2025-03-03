/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-tee.h"
#include "istream-try.h"
#include "ostream.h"
#include "iostream-temp.h"
#include "settings.h"
#include "compression.h"
#include "fs-api-private.h"

#define FS_COMPRESS_ISTREAM_MIN_BUFFER_SIZE 1024

struct compress_fs {
	struct fs fs;
	const struct compression_handler *compress_handler;
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

struct fs_compress_settings {
	pool_t pool;
	const char *fs_compress_write_method;
	bool fs_compress_read_plain_fallback;
};

#define COMPRESS_FS(ptr)	container_of((ptr), struct compress_fs, fs)
#define COMPRESS_FILE(ptr)	container_of((ptr), struct compress_fs_file, file)

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct fs_compress_settings)
static const struct setting_define fs_compress_setting_defines[] = {
	DEF(STR, fs_compress_write_method),
	DEF(BOOL, fs_compress_read_plain_fallback),

	SETTING_DEFINE_LIST_END
};
static const struct fs_compress_settings fs_compress_default_settings = {
	.fs_compress_write_method = "",
	.fs_compress_read_plain_fallback = FALSE,
};

const struct setting_parser_info fs_compress_setting_parser_info = {
	.name = "fs_compress",
	.plugin_dependency = "libfs_compress",

	.defines = fs_compress_setting_defines,
	.defaults = &fs_compress_default_settings,

	.struct_size = sizeof(struct fs_compress_settings),
	.pool_offset1 = 1 + offsetof(struct fs_compress_settings, pool),
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
fs_compress_init(struct fs *_fs, const struct fs_parameters *params,
		 const char **error_r)
{
	struct compress_fs *fs = COMPRESS_FS(_fs);
	const struct fs_compress_settings *set;
	int ret;

	if (settings_get(_fs->event, &fs_compress_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;
	fs->try_plain = set->fs_compress_read_plain_fallback;

	ret = set->fs_compress_write_method[0] == '\0' ? 1 :
		compression_lookup_handler(set->fs_compress_write_method,
					   &fs->compress_handler);
	if (ret <= 0) {
		*error_r = t_strdup_printf("Compression method '%s' %s.",
			set->fs_compress_write_method,
			ret == 0 ? "not supported" : "unknown");
		settings_free(set);
		return -1;
	}
	settings_free(set);

	return fs_init_parent(_fs, params, error_r);
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

static void fs_compress_set_metadata(struct fs_file *_file,
				     const char *key, const char *value)
{
	struct compress_fs_file *file = COMPRESS_FILE(_file);

	fs_set_metadata(_file->parent, key, value);
	if (file->super_read != NULL)
		fs_set_metadata(file->super_read, key, value);
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

	input = fs_read_stream(file->super_read,
		I_MAX(FS_COMPRESS_ISTREAM_MIN_BUFFER_SIZE, max_buffer_size));
	if (input->stream_errno != 0) {
		file->input = input;
		i_stream_ref(file->input);
		return file->input;
	}
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

	if (file->fs->compress_handler == NULL) {
		fs_wrapper_write_stream(_file);
		return;
	}

	i_assert(_file->output == NULL);

	file->temp_output =
		iostream_temp_create_named(_file->fs->temp_path_prefix,
					   IOSTREAM_TEMP_FLAG_TRY_FD_DUP,
					   fs_file_path(_file));
	_file->output = file->fs->compress_handler->
		create_ostream_auto(file->temp_output, _file->event);
}

static int fs_compress_write_stream_finish(struct fs_file *_file, bool success)
{
	struct compress_fs_file *file = COMPRESS_FILE(_file);
	struct istream *input;
	int ret;

	if (file->fs->compress_handler == NULL)
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
		.set_metadata = fs_compress_set_metadata,
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
