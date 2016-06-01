/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "istream.h"
#include "istream-private.h"
#include "istream-concat.h"
#include "istream-metawrap.h"
#include "ostream.h"
#include "ostream-metawrap.h"
#include "iostream-temp.h"
#include "fs-api-private.h"

struct metawrap_fs {
	struct fs fs;
	bool wrap_metadata;
};

struct metawrap_fs_file {
	struct fs_file file;
	struct metawrap_fs *fs;
	struct fs_file *super, *super_read;
	enum fs_open_mode open_mode;
	struct istream *input;
	bool metadata_read;

	struct ostream *super_output;
	struct ostream *temp_output;
	string_t *metadata_header;
	uoff_t metadata_write_size;
	bool metadata_changed_since_write;
};

struct metawrap_fs_iter {
	struct fs_iter iter;
	struct fs_iter *super;
};

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
	if (fs_init(parent_name, parent_args, set, &_fs->parent, &error) < 0) {
		fs_set_error(_fs, "%s", error);
		return -1;
	}
	if ((fs_get_properties(_fs->parent) & FS_PROPERTY_METADATA) == 0)
		fs->wrap_metadata = TRUE;
	return 0;
}

static void fs_metawrap_deinit(struct fs *_fs)
{
	struct metawrap_fs *fs = (struct metawrap_fs *)_fs;

	if (_fs->parent != NULL)
		fs_deinit(&_fs->parent);
	i_free(fs);
}

static enum fs_properties fs_metawrap_get_properties(struct fs *_fs)
{
	const struct metawrap_fs *fs = (const struct metawrap_fs *)_fs;
	enum fs_properties props;

	props = fs_get_properties(_fs->parent);
	if (fs->wrap_metadata) {
		/* we don't have a quick stat() to see the file's size,
		   because of the metadata header */
		props &= ~FS_PROPERTY_STAT;
		/* Copying can copy the whole metadata. */
		props |= FS_PROPERTY_COPY_METADATA;
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

	file->super = fs_file_init(_fs->parent, path, mode | flags);
	if (file->fs->wrap_metadata && mode == FS_OPEN_MODE_READONLY &&
	    (flags & FS_OPEN_FLAG_ASYNC) == 0) {
		/* use async stream for super, so fs_read_stream() won't create
		   another seekable stream unneededly */
		file->super_read = fs_file_init(_fs->parent, path, mode | flags |
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

	if (file->super_read != file->super && file->super_read != NULL)
		fs_file_deinit(&file->super_read);
	if (file->metadata_header != NULL)
		str_free(&file->metadata_header);
	fs_file_deinit(&file->super);
	i_free(file->file.path);
	i_free(file);
}

static void fs_metawrap_file_close(struct fs_file *_file)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (file->input != NULL)
		i_stream_unref(&file->input);
	if (file->super_read != NULL)
		fs_file_close(file->super_read);
	if (file->super != NULL)
		fs_file_close(file->super);
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
	return fs_wait_async(_fs->parent);
}

static void
fs_metawrap_set_metadata(struct fs_file *_file, const char *key,
			 const char *value)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (!file->fs->wrap_metadata)
		fs_set_metadata(file->super, key, value);
	else {
		fs_default_set_metadata(_file, key, value);
		file->metadata_changed_since_write = TRUE;
	}
}

static int
fs_metawrap_get_metadata(struct fs_file *_file,
			 const ARRAY_TYPE(fs_metadata) **metadata_r)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;
	ssize_t ret;
	char c;

	if (!file->fs->wrap_metadata)
		return fs_get_metadata(file->super, metadata_r);

	if (file->metadata_read) {
		/* we have the metadata */
	} else if (file->input == NULL) {
		if (fs_read(_file, &c, 1) < 0)
			return -1;
	} else {
		/* use the existing istream to read it */
		while ((ret = i_stream_read(file->input)) == 0) {
			if (file->metadata_read)
				break;

			i_assert(!file->input->blocking);
			if (fs_wait_async(_file->fs) < 0)
				return -1;
		}
		if (ret == -1 && file->input->stream_errno != 0) {
			fs_set_error(_file->fs, "read(%s) failed: %s",
				     i_stream_get_name(file->input),
				     i_stream_get_error(file->input));
			return -1;
		}
		i_assert(file->metadata_read);
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

	if (!file->fs->wrap_metadata)
		return fs_read(file->super, buf, size);
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

	input = fs_read_stream(file->super_read, max_buffer_size);
	file->input = i_stream_create_metawrap(input, fs_metawrap_callback, file);
	i_stream_unref(&input);
	i_stream_ref(file->input);
	return file->input;
}

static int fs_metawrap_write(struct fs_file *_file, const void *data, size_t size)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	if (!file->fs->wrap_metadata)
		return fs_write(file->super, data, size);
	return fs_write_via_stream(_file, data, size);
}

static void
fs_metawrap_append_metadata(struct metawrap_fs_file *file, string_t *str)
{
	const struct fs_metadata *metadata;

	array_foreach(&file->file.metadata, metadata) {
		if (strncmp(metadata->key, FS_METADATA_INTERNAL_PREFIX,
			    strlen(FS_METADATA_INTERNAL_PREFIX)) == 0)
			continue;

		str_append_tabescaped(str, metadata->key);
		str_append_c(str, ':');
		str_append_tabescaped(str, metadata->value);
		str_append_c(str, '\n');
	}
	str_append_c(str, '\n');
}

static void fs_metawrap_write_metadata(void *context)
{
	struct metawrap_fs_file *file = context;
	string_t *str = t_str_new(256);
	ssize_t ret;

	fs_metawrap_append_metadata(file, str);
	file->metadata_write_size = str_len(str);

	ret = o_stream_send(file->file.output, str_data(str), str_len(str));
	if (ret < 0)
		o_stream_close(file->file.output);
	else
		i_assert((size_t)ret == str_len(str));
	file->metadata_changed_since_write = FALSE;
}

static void fs_metawrap_write_stream(struct fs_file *_file)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	i_assert(_file->output == NULL);

	if (!file->fs->wrap_metadata) {
		file->super_output = fs_write_stream(file->super);
		_file->output = file->super_output;
	} else {
		file->temp_output =
			iostream_temp_create_named(_file->fs->temp_path_prefix,
						   IOSTREAM_TEMP_FLAG_TRY_FD_DUP,
						   fs_file_path(_file));
		_file->output = o_stream_create_metawrap(file->temp_output,
			fs_metawrap_write_metadata, file);
	}
}

static struct istream *
fs_metawrap_create_updated_istream(struct metawrap_fs_file *file,
				   struct istream *input)
{
	struct istream *input2, *inputs[3];

	if (file->metadata_header != NULL)
		str_truncate(file->metadata_header, 0);
	else
		file->metadata_header = str_new(default_pool, 1024);
	fs_metawrap_append_metadata(file, file->metadata_header);
	inputs[0] = i_stream_create_from_data(str_data(file->metadata_header),
					       str_len(file->metadata_header));

	i_stream_seek(input, file->metadata_write_size);
	inputs[1] = i_stream_create_limit(input, (uoff_t)-1);
	inputs[2] = NULL;
	input2 = i_stream_create_concat(inputs);
	i_stream_unref(&inputs[0]);
	i_stream_unref(&inputs[1]);

	file->metadata_write_size = str_len(file->metadata_header);
	return input2;
}

static int fs_metawrap_write_stream_finish(struct fs_file *_file, bool success)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;
	struct istream *input;
	int ret;

	if (_file->output != NULL) {
		if (_file->output == file->super_output)
			_file->output = NULL;
		else
			o_stream_unref(&_file->output);
	}
	if (!success) {
		if (file->super_output != NULL) {
			/* no metawrap */
			i_assert(file->temp_output == NULL);
			fs_write_stream_abort(file->super, &file->super_output);
		} else if (file->temp_output == NULL) {
			/* finishing up */
			i_assert(file->super_output == NULL);
			fs_write_stream_abort(file->super, &file->super_output);
		} else {
			o_stream_destroy(&file->temp_output);
		}
		return -1;
	}

	if (file->super_output != NULL) {
		/* no metawrap */
		i_assert(file->temp_output == NULL);
		return fs_write_stream_finish(file->super, &file->super_output);
	}
	if (file->temp_output == NULL) {
		/* finishing up */
		i_assert(file->super_output == NULL);
		return fs_write_stream_finish_async(file->super);
	}
	/* finish writing the temporary file */
	input = iostream_temp_finish(&file->temp_output, IO_BLOCK_SIZE);
	if (file->metadata_changed_since_write) {
		/* we'll need to recreate the metadata. do this by creating a
		   new istream combining the new metadata header and the
		   old body. */
		struct istream *input2 = input;

		input = fs_metawrap_create_updated_istream(file, input);
		i_stream_unref(&input2);
	}
	file->super_output = fs_write_stream(file->super);
	(void)o_stream_send_istream(file->super_output, input);
	if (input->stream_errno != 0) {
		fs_set_error(_file->fs, "read(%s) failed: %s",
			     i_stream_get_name(input),
			     i_stream_get_error(input));
		fs_write_stream_abort(file->super, &file->super_output);
		ret = -1;
	} else if (file->super_output->stream_errno != 0) {
		fs_set_error(_file->fs, "write(%s) failed: %s",
			     o_stream_get_name(file->super_output),
			     o_stream_get_error(file->super_output));
		fs_write_stream_abort(file->super, &file->super_output);
		ret = -1;
	} else {
		i_assert(i_stream_is_eof(input));
		ret = fs_write_stream_finish(file->super, &file->super_output);
	}
	i_stream_unref(&input);
	return ret;
}

static int
fs_metawrap_lock(struct fs_file *_file, unsigned int secs, struct fs_lock **lock_r)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	return fs_lock(file->super, secs, lock_r);
}

static void fs_metawrap_unlock(struct fs_lock *_lock ATTR_UNUSED)
{
	i_unreached();
}

static int fs_metawrap_exists(struct fs_file *_file)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	return fs_exists(file->super);
}

static int fs_metawrap_stat(struct fs_file *_file, struct stat *st_r)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;
	struct istream *input;
	uoff_t input_size;
	ssize_t ret;

	if (!file->fs->wrap_metadata)
		return fs_stat(file->super, st_r);

	if (file->metadata_write_size != 0) {
		/* fs_stat() after a write. we can do this quickly. */
		if (fs_stat(file->super, st_r) < 0)
			return -1;
		if ((uoff_t)st_r->st_size < file->metadata_write_size) {
			fs_set_error(_file->fs,
				"Just-written %s shrank unexpectedly "
				"(%"PRIuUOFF_T" < %"PRIuUOFF_T")",
				fs_file_path(_file), st_r->st_size,
				file->metadata_write_size);
			return -1;
		}
		st_r->st_size -= file->metadata_write_size;
		return 0;
	}

	if (file->input == NULL)
		input = fs_read_stream(_file, IO_BLOCK_SIZE);
	else {
		input = file->input;
		i_stream_ref(input);
	}
	if ((ret = i_stream_get_size(input, TRUE, &input_size)) < 0) {
		fs_set_error(_file->fs, "i_stream_get_size(%s) failed: %s",
			     fs_file_path(_file), i_stream_get_error(input));
		i_stream_unref(&input);
		return -1;
	}
	i_stream_unref(&input);
	if (ret == 0) {
		/* we shouldn't get here */
		fs_set_error(_file->fs, "i_stream_get_size(%s) returned size as unknown",
			     fs_file_path(_file));
		errno = EIO;
		return -1;
	}

	if (fs_stat(file->super, st_r) < 0) {
		i_assert(errno != EAGAIN); /* read should have caught this */
		return -1;
	}
	st_r->st_size = input_size;
	return 0;
}

static int fs_metawrap_copy(struct fs_file *_src, struct fs_file *_dest)
{
	struct metawrap_fs_file *src = (struct metawrap_fs_file *)_src;
	struct metawrap_fs_file *dest = (struct metawrap_fs_file *)_dest;

	if (!dest->fs->wrap_metadata || !_dest->metadata_changed) {
		if (_src != NULL)
			return fs_copy(src->super, dest->super);
		else
			return fs_copy_finish_async(dest->super);
	}
	return fs_default_copy(_src, _dest);
}

static int fs_metawrap_rename(struct fs_file *_src, struct fs_file *_dest)
{
	struct metawrap_fs_file *src = (struct metawrap_fs_file *)_src;
	struct metawrap_fs_file *dest = (struct metawrap_fs_file *)_dest;

	return fs_rename(src->super, dest->super);
}

static int fs_metawrap_delete(struct fs_file *_file)
{
	struct metawrap_fs_file *file = (struct metawrap_fs_file *)_file;

	return fs_delete(file->super);
}

static struct fs_iter *
fs_metawrap_iter_init(struct fs *_fs, const char *path,
		      enum fs_iter_flags flags)
{
	struct metawrap_fs_iter *iter;

	iter = i_new(struct metawrap_fs_iter, 1);
	iter->iter.fs = _fs;
	iter->iter.flags = flags;
	iter->super = fs_iter_init(_fs->parent, path, flags);
	return &iter->iter;
}

static const char *fs_metawrap_iter_next(struct fs_iter *_iter)
{
	struct metawrap_fs_iter *iter = (struct metawrap_fs_iter *)_iter;
	const char *fname;

	iter->super->async_callback = _iter->async_callback;
	iter->super->async_context = _iter->async_context;

	fname = fs_iter_next(iter->super);
	_iter->async_have_more = iter->super->async_have_more;
	return fname;
}

static int fs_metawrap_iter_deinit(struct fs_iter *_iter)
{
	struct metawrap_fs_iter *iter = (struct metawrap_fs_iter *)_iter;
	int ret;

	ret = fs_iter_deinit(&iter->super);
	i_free(iter);
	return ret;
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
		fs_metawrap_file_close,
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
		fs_metawrap_iter_next,
		fs_metawrap_iter_deinit
	}
};
