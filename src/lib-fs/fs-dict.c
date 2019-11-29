/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "guid.h"
#include "hex-binary.h"
#include "base64.h"
#include "istream.h"
#include "ostream.h"
#include "dict.h"
#include "fs-api-private.h"

enum fs_dict_value_encoding {
	FS_DICT_VALUE_ENCODING_RAW,
	FS_DICT_VALUE_ENCODING_HEX,
	FS_DICT_VALUE_ENCODING_BASE64
};

struct dict_fs {
	struct fs fs;
	struct dict *dict;
	char *path_prefix;
	enum fs_dict_value_encoding encoding;
};

struct dict_fs_file {
	struct fs_file file;
	pool_t pool;
	const char *key, *value;
	buffer_t *write_buffer;
};

struct dict_fs_iter {
	struct fs_iter iter;
	struct dict_iterate_context *dict_iter;
};

static struct fs *fs_dict_alloc(void)
{
	struct dict_fs *fs;

	fs = i_new(struct dict_fs, 1);
	fs->fs = fs_class_dict;
	return &fs->fs;
}

static int
fs_dict_init(struct fs *_fs, const char *args, const struct fs_settings *set,
	     const char **error_r)
{
	struct dict_fs *fs = (struct dict_fs *)_fs;
	struct dict_settings dict_set;
	const char *p, *encoding_str, *error;

	p = strchr(args, ':');
	if (p == NULL) {
		*error_r = "':' missing in args";
		return -1;
	}
	encoding_str = t_strdup_until(args, p++);
	if (strcmp(encoding_str, "raw") == 0)
		fs->encoding = FS_DICT_VALUE_ENCODING_RAW;
	else if (strcmp(encoding_str, "hex") == 0)
		fs->encoding = FS_DICT_VALUE_ENCODING_HEX;
	else if (strcmp(encoding_str, "base64") == 0)
		fs->encoding = FS_DICT_VALUE_ENCODING_BASE64;
	else {
		*error_r = t_strdup_printf("Unknown value encoding '%s'",
					   encoding_str);
		return -1;
	}

	i_zero(&dict_set);
	dict_set.username = set->username;
	dict_set.base_dir = set->base_dir;

	if (dict_init(p, &dict_set, &fs->dict, &error) < 0) {
		*error_r = t_strdup_printf("dict_init(%s) failed: %s",
					   args, error);
		return -1;
	}
	return 0;
}

static void fs_dict_deinit(struct fs *_fs)
{
	struct dict_fs *fs = (struct dict_fs *)_fs;

	dict_deinit(&fs->dict);
	i_free(fs);
}

static enum fs_properties fs_dict_get_properties(struct fs *fs ATTR_UNUSED)
{
	return FS_PROPERTY_ITER | FS_PROPERTY_RELIABLEITER;
}

static struct fs_file *fs_dict_file_alloc(void)
{
	struct dict_fs_file *file;
	pool_t pool;

	pool = pool_alloconly_create("fs dict file", 128);
	file = p_new(pool, struct dict_fs_file, 1);
	file->pool = pool;
	return &file->file;
}

static void
fs_dict_file_init(struct fs_file *_file, const char *path,
		  enum fs_open_mode mode, enum fs_open_flags flags ATTR_UNUSED)
{
	struct dict_fs_file *file = (struct dict_fs_file *)_file;
	struct dict_fs *fs = (struct dict_fs *)_file->fs;
	guid_128_t guid;

	i_assert(mode != FS_OPEN_MODE_APPEND); /* not supported */
	i_assert(mode != FS_OPEN_MODE_CREATE); /* not supported */

	if (mode != FS_OPEN_MODE_CREATE_UNIQUE_128)
		file->file.path = p_strdup(file->pool, path);
	else {
		guid_128_generate(guid);
		file->file.path = p_strdup_printf(file->pool, "%s/%s", path,
						  guid_128_to_string(guid));
	}
	file->key = fs->path_prefix == NULL ?
		p_strdup(file->pool, file->file.path) :
		p_strconcat(file->pool, fs->path_prefix, file->file.path, NULL);
}

static void fs_dict_file_deinit(struct fs_file *_file)
{
	struct dict_fs_file *file = (struct dict_fs_file *)_file;

	i_assert(_file->output == NULL);

	pool_unref(&file->pool);
}

static bool fs_dict_prefetch(struct fs_file *_file ATTR_UNUSED,
			     uoff_t length ATTR_UNUSED)
{
	/* once async dict_lookup() is implemented, we want to start it here */
	return TRUE;
}

static int fs_dict_lookup(struct dict_fs_file *file)
{
	struct dict_fs *fs = (struct dict_fs *)file->file.fs;
	const char *error;
	int ret;

	if (file->value != NULL)
		return 0;

	ret = dict_lookup(fs->dict, file->pool, file->key, &file->value, &error);
	if (ret > 0)
		return 0;
	else if (ret < 0) {
		errno = EIO;
		fs_set_error(file->file.event, "dict_lookup(%s) failed: %s", file->key, error);
		return -1;
	} else {
		errno = ENOENT;
		fs_set_error(file->file.event, "Dict key %s doesn't exist", file->key);
		return -1;
	}
}

static struct istream *
fs_dict_read_stream(struct fs_file *_file, size_t max_buffer_size ATTR_UNUSED)
{
	struct dict_fs_file *file = (struct dict_fs_file *)_file;
	struct istream *input;

	if (fs_dict_lookup(file) < 0)
		input = i_stream_create_error_str(errno, "%s", fs_file_last_error(_file));
	else
		input = i_stream_create_from_data(file->value, strlen(file->value));
	i_stream_set_name(input, file->key);
	return input;
}

static void fs_dict_write_stream(struct fs_file *_file)
{
	struct dict_fs_file *file = (struct dict_fs_file *)_file;

	i_assert(_file->output == NULL);

	file->write_buffer = buffer_create_dynamic(file->pool, 128);
	_file->output = o_stream_create_buffer(file->write_buffer);
	o_stream_set_name(_file->output, file->key);
}

static void fs_dict_write_rename_if_needed(struct dict_fs_file *file)
{
	struct dict_fs *fs = (struct dict_fs *)file->file.fs;
	const char *new_fname;

	new_fname = fs_metadata_find(&file->file.metadata, FS_METADATA_WRITE_FNAME);
	if (new_fname == NULL)
		return;

	file->file.path = p_strdup(file->pool, new_fname);
	file->key = fs->path_prefix == NULL ? p_strdup(file->pool, new_fname) :
		p_strconcat(file->pool, fs->path_prefix, new_fname, NULL);
}

static int fs_dict_write_stream_finish(struct fs_file *_file, bool success)
{
	struct dict_fs_file *file = (struct dict_fs_file *)_file;
	struct dict_fs *fs = (struct dict_fs *)_file->fs;
	struct dict_transaction_context *trans;
	const char *error;

	o_stream_destroy(&_file->output);
	if (!success)
		return -1;

	fs_dict_write_rename_if_needed(file);
	trans = dict_transaction_begin(fs->dict);
	switch (fs->encoding) {
	case FS_DICT_VALUE_ENCODING_RAW:
		dict_set(trans, file->key, str_c(file->write_buffer));
		break;
	case FS_DICT_VALUE_ENCODING_HEX: {
		string_t *hex = t_str_new(file->write_buffer->used * 2 + 1);
		binary_to_hex_append(hex, file->write_buffer->data,
				     file->write_buffer->used);
		dict_set(trans, file->key, str_c(hex));
		break;
	}
	case FS_DICT_VALUE_ENCODING_BASE64: {
		const size_t base64_size =
			MAX_BASE64_ENCODED_SIZE(file->write_buffer->used);
		string_t *base64 = t_str_new(base64_size);
		base64_encode(file->write_buffer->data,
			      file->write_buffer->used, base64);
		dict_set(trans, file->key, str_c(base64));
	}
	}
	if (dict_transaction_commit(&trans, &error) < 0) {
		errno = EIO;
		fs_set_error(_file->event, "Dict transaction commit failed: %s", error);
		return -1;
	}
	return 1;
}

static int fs_dict_stat(struct fs_file *_file, struct stat *st_r)
{
	struct dict_fs_file *file = (struct dict_fs_file *)_file;

	i_zero(st_r);

	if (fs_dict_lookup(file) < 0)
		return -1;
	st_r->st_size = strlen(file->value);
	return 0;
}

static int fs_dict_delete(struct fs_file *_file)
{
	struct dict_fs_file *file = (struct dict_fs_file *)_file;
	struct dict_fs *fs = (struct dict_fs *)_file->fs;
	struct dict_transaction_context *trans;
	const char *error;

	trans = dict_transaction_begin(fs->dict);
	dict_unset(trans, file->key);
	if (dict_transaction_commit(&trans, &error) < 0) {
		errno = EIO;
		fs_set_error(_file->event, "Dict transaction commit failed: %s", error);
		return -1;
	}
	return 0;
}

static struct fs_iter *fs_dict_iter_alloc(void)
{
	struct dict_fs_iter *iter = i_new(struct dict_fs_iter, 1);
	return &iter->iter;
}

static void
fs_dict_iter_init(struct fs_iter *_iter, const char *path,
		  enum fs_iter_flags flags ATTR_UNUSED)
{
	struct dict_fs_iter *iter = (struct dict_fs_iter *)_iter;
	struct dict_fs *fs = (struct dict_fs *)_iter->fs;

	if (fs->path_prefix != NULL)
		path = t_strconcat(fs->path_prefix, path, NULL);

	iter->dict_iter = dict_iterate_init(fs->dict, path, 0);
}

static const char *fs_dict_iter_next(struct fs_iter *_iter)
{
	struct dict_fs_iter *iter = (struct dict_fs_iter *)_iter;
	const char *key, *value;

	if (!dict_iterate(iter->dict_iter, &key, &value))
		return NULL;
	return key;
}

static int fs_dict_iter_deinit(struct fs_iter *_iter)
{
	struct dict_fs_iter *iter = (struct dict_fs_iter *)_iter;
	const char *error;
	int ret;

	ret = dict_iterate_deinit(&iter->dict_iter, &error);
	if (ret < 0)
		fs_set_error(_iter->event, "Dict iteration failed: %s", error);
	return ret;
}

const struct fs fs_class_dict = {
	.name = "dict",
	.v = {
		fs_dict_alloc,
		fs_dict_init,
		fs_dict_deinit,
		fs_dict_get_properties,
		fs_dict_file_alloc,
		fs_dict_file_init,
		fs_dict_file_deinit,
		NULL,
		NULL,
		NULL, NULL,
		fs_default_set_metadata,
		NULL,
		fs_dict_prefetch,
		NULL,
		fs_dict_read_stream,
		NULL,
		fs_dict_write_stream,
		fs_dict_write_stream_finish,
		NULL,
		NULL,
		NULL,
		fs_dict_stat,
		fs_default_copy,
		NULL,
		fs_dict_delete,
		fs_dict_iter_alloc,
		fs_dict_iter_init,
		fs_dict_iter_next,
		fs_dict_iter_deinit,
		NULL,
		NULL
	}
};
