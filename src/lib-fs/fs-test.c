/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"
#include "fs-test.h"

static struct fs *fs_test_alloc(void)
{
	struct test_fs *fs;

	fs = i_new(struct test_fs, 1);
	fs->fs = fs_class_test;
	i_array_init(&fs->iter_files, 32);
	return &fs->fs;
}

static int
fs_test_init(struct fs *_fs ATTR_UNUSED, const char *args ATTR_UNUSED,
	     const struct fs_settings *set ATTR_UNUSED,
	     const char **error_r ATTR_UNUSED)
{
	return 0;
}

static void fs_test_free(struct fs *_fs)
{
	struct test_fs *fs = (struct test_fs *)_fs;

	array_free(&fs->iter_files);
	i_free(fs);
}

static enum fs_properties fs_test_get_properties(struct fs *_fs)
{
	struct test_fs *fs = (struct test_fs *)_fs;

	return fs->properties;
}

static struct fs_file *fs_test_file_alloc(void)
{
	struct test_fs_file *file = i_new(struct test_fs_file, 1);
	return &file->file;
}

static void
fs_test_file_init(struct fs_file *_file, const char *path,
		  enum fs_open_mode mode, enum fs_open_flags flags)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	file->file.path = i_strdup(path);
	file->file.flags = flags;
	file->mode = mode;
	file->contents = buffer_create_dynamic(default_pool, 1024);
	file->exists = TRUE;
	file->seekable = TRUE;
	file->wait_async = (flags & FS_OPEN_FLAG_ASYNC) != 0;
}

static void fs_test_file_deinit(struct fs_file *_file)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	fs_file_free(_file);
	buffer_free(&file->contents);
	i_free(file->file.path);
	i_free(file);
}

static void fs_test_file_close(struct fs_file *_file)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	file->closed = TRUE;
}

static const char *fs_test_file_get_path(struct fs_file *_file)
{
	return _file->path;
}

static void
fs_test_set_async_callback(struct fs_file *_file,
			   fs_file_async_callback_t *callback,
			   void *context)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	file->async_callback = callback;
	file->async_context = context;
}

static void fs_test_wait_async(struct fs *_fs ATTR_UNUSED)
{
}

static void
fs_test_set_metadata(struct fs_file *_file, const char *key,
		     const char *value)
{
	if (strcmp(key, FS_METADATA_WRITE_FNAME) == 0) {
		i_free(_file->path);
		_file->path = i_strdup(value);
	} else {
		fs_default_set_metadata(_file, key, value);
	}
}

static int
fs_test_get_metadata(struct fs_file *_file,
		     enum fs_get_metadata_flags flags,
		     const ARRAY_TYPE(fs_metadata) **metadata_r)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	if ((flags & FS_GET_METADATA_FLAG_LOADED_ONLY) != 0) {
		*metadata_r = &_file->metadata;
		return 0;
	}

	if (file->wait_async) {
		fs_file_set_error_async(_file);
		return -1;
	}
	if (file->io_failure) {
		errno = EIO;
		return -1;
	}
	fs_metadata_init(_file);
	*metadata_r = &_file->metadata;
	return 0;
}

static bool fs_test_prefetch(struct fs_file *_file ATTR_UNUSED,
			     uoff_t length ATTR_UNUSED)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	file->prefetched = TRUE;
	return TRUE;
}

static void fs_test_stream_destroyed(struct test_fs_file *file)
{
	i_assert(file->input != NULL);
	file->input = NULL;
}

static struct istream *
fs_test_read_stream(struct fs_file *_file, size_t max_buffer_size ATTR_UNUSED)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;
	struct istream *input;

	i_assert(file->input == NULL);

	if (!file->exists)
		return i_stream_create_error(ENOENT);
	if (file->io_failure)
		return i_stream_create_error(EIO);
	input = test_istream_create_data(file->contents->data,
					 file->contents->used);
	i_stream_add_destroy_callback(input, fs_test_stream_destroyed, file);
	if (!file->seekable)
		input->seekable = FALSE;
	file->input = input;
	return input;
}

static void fs_test_write_stream(struct fs_file *_file)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	i_assert(_file->output == NULL);

	buffer_set_used_size(file->contents, 0);
	_file->output = o_stream_create_buffer(file->contents);
}

static int fs_test_write_stream_finish(struct fs_file *_file, bool success)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	o_stream_destroy(&_file->output);
	if (file->wait_async) {
		fs_file_set_error_async(_file);
		return 0;
	}
	if (file->io_failure)
		success = FALSE;
	if (!success)
		buffer_set_used_size(file->contents, 0);
	return success ? 1 : -1;
}

static int
fs_test_lock(struct fs_file *_file, unsigned int secs ATTR_UNUSED,
	     struct fs_lock **lock_r)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	if (file->locked)
		return 0;
	file->locked = TRUE;
	*lock_r = i_new(struct fs_lock, 1);
	(*lock_r)->file = _file;
	return 1;
}

static void fs_test_unlock(struct fs_lock *lock)
{
	struct test_fs_file *file = (struct test_fs_file *)lock->file;

	file->locked = FALSE;
	i_free(lock);
}

static int fs_test_exists(struct fs_file *_file)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	if (file->wait_async) {
		fs_file_set_error_async(_file);
		return -1;
	}
	if (file->io_failure) {
		errno = EIO;
		return -1;
	}
	return file->exists ? 1 : 0;
}

static int fs_test_stat(struct fs_file *_file, struct stat *st_r)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	if (file->wait_async) {
		fs_file_set_error_async(_file);
		return -1;
	}
	if (file->io_failure) {
		errno = EIO;
		return -1;
	}
	if (!file->exists) {
		errno = ENOENT;
		return -1;
	}
	i_zero(st_r);
	st_r->st_size = file->contents->used;
	return 0;
}

static int fs_test_copy(struct fs_file *_src, struct fs_file *_dest)
{
	struct test_fs_file *src;
	struct test_fs_file *dest = (struct test_fs_file *)_dest;

	if (_src != NULL)
		dest->copy_src = test_fs_file_get(_src->fs, fs_file_path(_src));
	src = dest->copy_src;
	if (dest->wait_async) {
		fs_file_set_error_async(_dest);
		return -1;
	}
	dest->copy_src = NULL;

	if (dest->io_failure) {
		errno = EIO;
		return -1;
	}
	if (!src->exists) {
		errno = ENOENT;
		return -1;
	}
	buffer_set_used_size(dest->contents, 0);
	buffer_append_buf(dest->contents, src->contents, 0, (size_t)-1);
	dest->exists = TRUE;
	return 0;
}

static int fs_test_rename(struct fs_file *_src, struct fs_file *_dest)
{
	struct test_fs_file *src = (struct test_fs_file *)_src;
	struct test_fs_file *dest = (struct test_fs_file *)_dest;

	if (src->wait_async || dest->wait_async) {
		fs_file_set_error_async(_dest);
		return -1;
	}

	if (fs_test_copy(_src, _dest) < 0)
		return -1;
	src->exists = FALSE;
	return 0;
}

static int fs_test_delete(struct fs_file *_file)
{
	struct test_fs_file *file = (struct test_fs_file *)_file;

	if (file->wait_async) {
		fs_file_set_error_async(_file);
		return -1;
	}

	if (!file->exists) {
		errno = ENOENT;
		return -1;
	}
	return 0;
}

static struct fs_iter *fs_test_iter_alloc(void)
{
	struct test_fs_iter *iter = i_new(struct test_fs_iter, 1);
	return &iter->iter;
}

static void
fs_test_iter_init(struct fs_iter *_iter, const char *path,
		  enum fs_iter_flags flags ATTR_UNUSED)
{
	struct test_fs_iter *iter = (struct test_fs_iter *)_iter;
	struct test_fs *fs = (struct test_fs *)_iter->fs;

	iter->prefix = i_strdup(path);
	iter->prefix_len = strlen(iter->prefix);
	iter->prev_dir = i_strdup("");
	array_sort(&fs->iter_files, i_strcmp_p);
}

static const char *fs_test_iter_next(struct fs_iter *_iter)
{
	struct test_fs_iter *iter = (struct test_fs_iter *)_iter;
	struct test_fs *fs = (struct test_fs *)_iter->fs;
	const char *const *files, *p;
	unsigned int count;
	size_t len, prev_dir_len = strlen(iter->prev_dir);

	files = array_get(&fs->iter_files, &count);
	for (; iter->idx < count; iter->idx++) {
		const char *fname = files[iter->idx];

		if (strncmp(fname, iter->prefix, iter->prefix_len) != 0)
			continue;
		p = strrchr(fname, '/');
		if ((_iter->flags & FS_ITER_FLAG_DIRS) == 0) {
			if (p == NULL)
				return fname;
			if (p[1] == '\0')
				continue; /* dir/ */
			return p+1;
		}

		if (p == NULL)
			continue;
		len = p - fname;
		if (len == 0)
			continue;
		if (len == prev_dir_len &&
		    strncmp(fname, iter->prev_dir, len) == 0)
			continue;
		i_free(iter->prev_dir);
		iter->prev_dir = i_strndup(fname, len);
		return iter->prev_dir;
	}
	return NULL;
}

static int fs_test_iter_deinit(struct fs_iter *_iter)
{
	struct test_fs_iter *iter = (struct test_fs_iter *)_iter;
	int ret = iter->failed ? -1 : 0;

	i_free(iter->prefix);
	return ret;
}

struct test_fs *test_fs_get(struct fs *fs)
{
	while (strcmp(fs->name, "test") != 0) {
		i_assert(fs->parent != NULL);
		fs = fs->parent;
	}
	return (struct test_fs *)fs;
}

struct test_fs_file *test_fs_file_get(struct fs *fs, const char *path)
{
	struct fs_file *file;

	fs = &test_fs_get(fs)->fs;

	for (file = fs->files;; file = file->next) {
		i_assert(file != NULL);
		if (strcmp(fs_file_path(file), path) == 0)
			break;
	}
	return (struct test_fs_file *)file;
}

const struct fs fs_class_test = {
	.name = "test",
	.v = {
		fs_test_alloc,
		fs_test_init,
		fs_test_free,
		fs_test_get_properties,
		fs_test_file_alloc,
		fs_test_file_init,
		fs_test_file_deinit,
		fs_test_file_close,
		fs_test_file_get_path,
		fs_test_set_async_callback,
		fs_test_wait_async,
		fs_test_set_metadata,
		fs_test_get_metadata,
		fs_test_prefetch,
		NULL,
		fs_test_read_stream,
		NULL,
		fs_test_write_stream,
		fs_test_write_stream_finish,
		fs_test_lock,
		fs_test_unlock,
		fs_test_exists,
		fs_test_stat,
		fs_test_copy,
		fs_test_rename,
		fs_test_delete,
		fs_test_iter_alloc,
		fs_test_iter_init,
		fs_test_iter_next,
		fs_test_iter_deinit,
		NULL,
		NULL,
	}
};
