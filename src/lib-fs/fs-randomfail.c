/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "istream-private.h"
#include "istream-concat.h"
#include "istream-failure-at.h"
#include "ostream-failure-at.h"
#include "ostream.h"
#include "fs-api-private.h"


#define RANDOMFAIL_ERROR "Random failure injection"

static const char *fs_op_names[FS_OP_COUNT] = {
	"wait", "metadata", "prefetch", "read", "write", "lock", "exists",
	"stat", "copy", "rename", "delete", "iter"
};

struct randomfail_fs {
	struct fs fs;
	unsigned int op_probability[FS_OP_COUNT];
	uoff_t range_start[FS_OP_COUNT], range_end[FS_OP_COUNT];
};

struct randomfail_fs_file {
	struct fs_file file;
	struct fs_file *super, *super_read;
	struct istream *input;
	bool op_pending[FS_OP_COUNT];

	struct ostream *super_output;
};

struct randomfail_fs_iter {
	struct fs_iter iter;
	struct fs_iter *super;
	unsigned int fail_pos;
};

static struct fs *fs_randomfail_alloc(void)
{
	struct randomfail_fs *fs;

	fs = i_new(struct randomfail_fs, 1);
	fs->fs = fs_class_randomfail;
	return &fs->fs;
}

static bool fs_op_find(const char *str, enum fs_op *op_r)
{
	enum fs_op op;

	for (op = 0; op < FS_OP_COUNT; op++) {
		if (strcmp(fs_op_names[op], str) == 0) {
			*op_r = op;
			return TRUE;
		}
	}
	return FALSE;
}

static bool
fs_randomfail_add_probability(struct randomfail_fs *fs,
			      const char *key, const char *value,
			      const char **error_r)
{
	unsigned int num;
	enum fs_op op;
	bool invalid_value = FALSE;

	if (str_to_uint(value, &num) < 0 || num > 100)
		invalid_value = TRUE;
	if (fs_op_find(key, &op)) {
		if (invalid_value) {
			*error_r = "Invalid probability value";
			return -1;
		}
		fs->op_probability[op] = num;
		return 1;
	}
	if (strcmp(key, "all") == 0) {
		if (invalid_value) {
			*error_r = "Invalid probability value";
			return -1;
		}
		for (op = 0; op < FS_OP_COUNT; op++)
			fs->op_probability[op] = num;
		return 1;
	}
	return 0;
}

static int
fs_randomfail_add_probability_range(struct randomfail_fs *fs,
				    const char *key, const char *value,
				    const char **error_r)
{
	enum fs_op op;
	const char *p;
	uoff_t num1, num2;

	if (strcmp(key, "read-range") == 0)
		op = FS_OP_READ;
	else if (strcmp(key, "write-range") == 0)
		op = FS_OP_WRITE;
	else if (strcmp(key, "iter-range") == 0)
		op = FS_OP_ITER;
	else
		return 0;

	p = strchr(value, '-');
	if (p == NULL) {
		if (str_to_uoff(value, &num1) < 0) {
			*error_r = "Invalid range value";
			return -1;
		}
		num2 = num1;
	} else if (str_to_uoff(t_strdup_until(value, p), &num1) < 0 ||
		   str_to_uoff(p+1, &num2) < 0 || num1 > num2) {
		*error_r = "Invalid range values";
		return -1;
	}
	fs->range_start[op] = num1;
	fs->range_end[op] = num2;
	return 1;
}

static int fs_randomfail_parse_params(struct randomfail_fs *fs,
				      const char *params, const char **error_r)
{
	const char *const *tmp;
	int ret;

	for (tmp = t_strsplit_spaces(params, ","); *tmp != NULL; tmp++) {
		const char *key = *tmp;
		const char *value = strchr(key, '=');

		if (value == NULL) {
			*error_r = "Missing '='";
			return -1;
		}
		key = t_strdup_until(key, value++);
		if ((ret = fs_randomfail_add_probability(fs, key, value, error_r)) != 0) {
			if (ret < 0)
				return -1;
			continue;
		}
		if ((ret = fs_randomfail_add_probability_range(fs, key, value, error_r)) != 0) {
			if (ret < 0)
				return -1;
			continue;
		}
		*error_r = t_strdup_printf("Unknown key '%s'", key);
		return -1;
	}
	return 0;
}

static int
fs_randomfail_init(struct fs *_fs, const char *args,
		   const struct fs_settings *set)
{
	struct randomfail_fs *fs = (struct randomfail_fs *)_fs;
	const char *p, *parent_name, *parent_args, *error;

	p = strchr(args, ':');
	if (p == NULL) {
		fs_set_error(_fs, "Randomfail parameters missing");
		return -1;
	}
	if (fs_randomfail_parse_params(fs, t_strdup_until(args, p++), &error) < 0) {
		fs_set_error(_fs, "Invalid randomfail parameters: %s", error);
		return -1;
	}
	args = p;

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
	return 0;
}

static void fs_randomfail_deinit(struct fs *_fs)
{
	struct randomfail_fs *fs = (struct randomfail_fs *)_fs;

	if (_fs->parent != NULL)
		fs_deinit(&_fs->parent);
	i_free(fs);
}

static enum fs_properties fs_randomfail_get_properties(struct fs *_fs)
{
	return fs_get_properties(_fs->parent);
}

static struct fs_file *
fs_randomfail_file_init(struct fs *_fs, const char *path,
			enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct randomfail_fs_file *file;

	file = i_new(struct randomfail_fs_file, 1);
	file->file.fs = _fs;
	file->file.path = i_strdup(path);
	file->super = fs_file_init(_fs->parent, path, mode | flags);
	return &file->file;
}

static void fs_randomfail_file_deinit(struct fs_file *_file)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;

	fs_file_deinit(&file->super);
	i_free(file->file.path);
	i_free(file);
}

static void fs_randomfail_file_close(struct fs_file *_file)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;

	fs_file_close(file->super);
}

static const char *fs_randomfail_file_get_path(struct fs_file *_file)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;

	return fs_file_path(file->super);
}

static void
fs_randomfail_set_async_callback(struct fs_file *_file,
				 fs_file_async_callback_t *callback,
				 void *context)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;

	fs_file_set_async_callback(file->super, callback, context);
}

static bool fs_random_fail(struct fs *_fs, int divider, enum fs_op op)
{
	struct randomfail_fs *fs = (struct randomfail_fs *)_fs;

	if (fs->op_probability[op] == 0)
		return FALSE;
	if ((unsigned int)(rand() % (100*divider)) <= fs->op_probability[op]) {
		fs_set_error(_fs, RANDOMFAIL_ERROR);
		return TRUE;
	}
	return FALSE;
}

static bool
fs_file_random_fail_begin(struct randomfail_fs_file *file, enum fs_op op)
{
	if (!file->op_pending[op]) {
		if (fs_random_fail(file->file.fs, 2, op))
			return TRUE;
	}
	file->op_pending[op] = TRUE;
	return FALSE;
}

static int
fs_file_random_fail_end(struct randomfail_fs_file *file,
			int ret, enum fs_op op)
{
	if (ret == 0 || errno != ENOENT) {
		if (fs_random_fail(file->file.fs, 2, op))
			return TRUE;
		file->op_pending[op] = FALSE;
	}
	return ret;
}

static bool
fs_random_fail_range(struct fs *_fs, enum fs_op op, uoff_t *offset_r)
{
	struct randomfail_fs *fs = (struct randomfail_fs *)_fs;

	if (!fs_random_fail(_fs, 1, op))
		return FALSE;
	*offset_r = fs->range_start[op] +
		rand() % (fs->range_end[op] - fs->range_start[op] + 1);
	return TRUE;
}

static int fs_randomfail_wait_async(struct fs *_fs)
{
	if (fs_random_fail(_fs, 1, FS_OP_WAIT))
		return -1;
	return fs_wait_async(_fs->parent);
}

static void
fs_randomfail_set_metadata(struct fs_file *_file, const char *key,
			   const char *value)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;

	fs_set_metadata(file->super, key, value);
}

static int
fs_randomfail_get_metadata(struct fs_file *_file,
			   const ARRAY_TYPE(fs_metadata) **metadata_r)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;
	int ret;

	if (fs_file_random_fail_begin(file, FS_OP_METADATA))
		return -1;
	ret = fs_get_metadata(file->super, metadata_r);
	return fs_file_random_fail_end(file, ret, FS_OP_METADATA);
}

static bool fs_randomfail_prefetch(struct fs_file *_file, uoff_t length)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;

	if (fs_random_fail(_file->fs, 1, FS_OP_PREFETCH))
		return TRUE;
	return fs_prefetch(file->super, length);
}

static ssize_t fs_randomfail_read(struct fs_file *_file, void *buf, size_t size)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;
	int ret;

	if (fs_file_random_fail_begin(file, FS_OP_READ))
		return -1;
	ret = fs_read(file->super, buf, size);
	return fs_file_random_fail_end(file, ret, FS_OP_READ);
}

static struct istream *
fs_randomfail_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;
	struct istream *input, *input2;
	uoff_t offset;

	input = fs_read_stream(file->super, max_buffer_size);
	if (!fs_random_fail_range(_file->fs, FS_OP_READ, &offset))
		return input;
	input2 = i_stream_create_failure_at(input, offset, RANDOMFAIL_ERROR);
	i_stream_unref(&input);
	return input2;
}

static int fs_randomfail_write(struct fs_file *_file, const void *data, size_t size)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;
	int ret;

	if (fs_file_random_fail_begin(file, FS_OP_WRITE))
		return -1;
	ret = fs_write(file->super, data, size);
	return fs_file_random_fail_end(file, ret, FS_OP_EXISTS);
}

static void fs_randomfail_write_stream(struct fs_file *_file)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;
	uoff_t offset;

	i_assert(_file->output == NULL);

	file->super_output = fs_write_stream(file->super);
	if (!fs_random_fail_range(_file->fs, FS_OP_WRITE, &offset))
		_file->output = file->super_output;
	else {
		_file->output = o_stream_create_failure_at(file->super_output, offset,
							   RANDOMFAIL_ERROR);
	}
}

static int fs_randomfail_write_stream_finish(struct fs_file *_file, bool success)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;

	if (_file->output != NULL) {
		if (_file->output == file->super_output)
			_file->output = NULL;
		else
			o_stream_unref(&_file->output);
		if (!success) {
			fs_write_stream_abort_parent(_file, &file->super_output);
			return -1;
		}
		if (!fs_random_fail(_file->fs, 1, FS_OP_WRITE)) {
			fs_write_stream_abort_error(file->super, &file->super_output, RANDOMFAIL_ERROR);
			return -1;
		}
	}
	return fs_write_stream_finish(file->super, &file->super_output);
}

static int
fs_randomfail_lock(struct fs_file *_file, unsigned int secs, struct fs_lock **lock_r)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;

	if (fs_random_fail(_file->fs, 1, FS_OP_LOCK))
		return -1;
	return fs_lock(file->super, secs, lock_r);
}

static void fs_randomfail_unlock(struct fs_lock *_lock ATTR_UNUSED)
{
	i_unreached();
}

static int fs_randomfail_exists(struct fs_file *_file)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;
	int ret;

	if (fs_file_random_fail_begin(file, FS_OP_EXISTS))
		return -1;
	ret = fs_exists(file->super);
	return fs_file_random_fail_end(file, ret, FS_OP_EXISTS);
}

static int fs_randomfail_stat(struct fs_file *_file, struct stat *st_r)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;
	int ret;

	if (fs_file_random_fail_begin(file, FS_OP_STAT))
		return -1;
	ret = fs_stat(file->super, st_r);
	return fs_file_random_fail_end(file, ret, FS_OP_STAT);
}

static int fs_randomfail_get_nlinks(struct fs_file *_file, nlink_t *nlinks_r)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;
	int ret;

	if (fs_file_random_fail_begin(file, FS_OP_STAT))
		return -1;
	ret = fs_get_nlinks(file->super, nlinks_r);
	return fs_file_random_fail_end(file, ret, FS_OP_STAT);
}

static int fs_randomfail_copy(struct fs_file *_src, struct fs_file *_dest)
{
	struct randomfail_fs_file *src = (struct randomfail_fs_file *)_src;
	struct randomfail_fs_file *dest = (struct randomfail_fs_file *)_dest;
	int ret;

	if (fs_file_random_fail_begin(dest, FS_OP_COPY))
		return -1;

	if (_src != NULL)
		ret = fs_copy(src->super, dest->super);
	else
		ret = fs_copy_finish_async(dest->super);
	return fs_file_random_fail_end(dest, ret, FS_OP_COPY);
}

static int fs_randomfail_rename(struct fs_file *_src, struct fs_file *_dest)
{
	struct randomfail_fs_file *src = (struct randomfail_fs_file *)_src;
	struct randomfail_fs_file *dest = (struct randomfail_fs_file *)_dest;
	int ret;

	if (fs_file_random_fail_begin(dest, FS_OP_RENAME))
		return -1;
	ret = fs_rename(src->super, dest->super);
	return fs_file_random_fail_end(dest, ret, FS_OP_RENAME);
}

static int fs_randomfail_delete(struct fs_file *_file)
{
	struct randomfail_fs_file *file = (struct randomfail_fs_file *)_file;
	int ret;

	if (fs_file_random_fail_begin(file, FS_OP_DELETE))
		return -1;
	ret = fs_delete(file->super);
	return fs_file_random_fail_end(file, ret, FS_OP_DELETE);
}

static struct fs_iter *
fs_randomfail_iter_init(struct fs *_fs, const char *path,
		      enum fs_iter_flags flags)
{
	struct randomfail_fs_iter *iter;
	uoff_t pos;

	iter = i_new(struct randomfail_fs_iter, 1);
	iter->iter.fs = _fs;
	iter->iter.flags = flags;
	iter->super = fs_iter_init(_fs->parent, path, flags);
	if (fs_random_fail_range(_fs, FS_OP_ITER, &pos))
		iter->fail_pos = pos + 1;
	return &iter->iter;
}

static const char *fs_randomfail_iter_next(struct fs_iter *_iter)
{
	struct randomfail_fs_iter *iter = (struct randomfail_fs_iter *)_iter;
	const char *fname;

	if (iter->fail_pos > 0) {
		if (iter->fail_pos == 1)
			return NULL;
		iter->fail_pos--;
	}

	iter->super->async_callback = _iter->async_callback;
	iter->super->async_context = _iter->async_context;

	fname = fs_iter_next(iter->super);
	_iter->async_have_more = iter->super->async_have_more;
	return fname;
}

static int fs_randomfail_iter_deinit(struct fs_iter *_iter)
{
	struct randomfail_fs_iter *iter = (struct randomfail_fs_iter *)_iter;
	int ret;

	ret = fs_iter_deinit(&iter->super);
	if (iter->fail_pos == 1) {
		fs_set_error(_iter->fs, RANDOMFAIL_ERROR);
		errno = EIO;
		ret = -1;
	}
	i_free(iter);
	return ret;
}

const struct fs fs_class_randomfail = {
	.name = "randomfail",
	.v = {
		fs_randomfail_alloc,
		fs_randomfail_init,
		fs_randomfail_deinit,
		fs_randomfail_get_properties,
		fs_randomfail_file_init,
		fs_randomfail_file_deinit,
		fs_randomfail_file_close,
		fs_randomfail_file_get_path,
		fs_randomfail_set_async_callback,
		fs_randomfail_wait_async,
		fs_randomfail_set_metadata,
		fs_randomfail_get_metadata,
		fs_randomfail_prefetch,
		fs_randomfail_read,
		fs_randomfail_read_stream,
		fs_randomfail_write,
		fs_randomfail_write_stream,
		fs_randomfail_write_stream_finish,
		fs_randomfail_lock,
		fs_randomfail_unlock,
		fs_randomfail_exists,
		fs_randomfail_stat,
		fs_randomfail_copy,
		fs_randomfail_rename,
		fs_randomfail_delete,
		fs_randomfail_iter_init,
		fs_randomfail_iter_next,
		fs_randomfail_iter_deinit,
		NULL,
		fs_randomfail_get_nlinks,
	}
};
