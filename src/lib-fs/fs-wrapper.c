/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fs-api-private.h"
#include "ostream.h"

struct wrapper_fs_iter {
	struct fs_iter iter;
	struct fs_iter *parent;
};

enum fs_properties fs_wrapper_get_properties(struct fs *fs)
{
	return fs_get_properties(fs->parent);
}

void fs_wrapper_file_close(struct fs_file *file)
{
	fs_file_close(file->parent);
}

const char *fs_wrapper_file_get_path(struct fs_file *file)
{
	return fs_file_path(file->parent);
}

void fs_wrapper_set_async_callback(struct fs_file *file,
				   fs_file_async_callback_t *callback,
				   void *context)
{
	fs_file_set_async_callback(file->parent, callback, context);
}

int fs_wrapper_wait_async(struct fs *fs)
{
	return fs_wait_async(fs->parent);
}

void fs_wrapper_set_metadata(struct fs_file *file, const char *key,
			     const char *value)
{
	fs_set_metadata(file->parent, key, value);
}

int fs_wrapper_get_metadata(struct fs_file *file,
			    const ARRAY_TYPE(fs_metadata) **metadata_r)
{
	return fs_get_metadata(file->parent, metadata_r);
}

bool fs_wrapper_prefetch(struct fs_file *file, uoff_t length)
{
	return fs_prefetch(file->parent, length);
}

ssize_t fs_wrapper_read(struct fs_file *file, void *buf, size_t size)
{
	return fs_read(file->parent, buf, size);
}

struct istream *
fs_wrapper_read_stream(struct fs_file *file, size_t max_buffer_size)
{
	return fs_read_stream(file->parent, max_buffer_size);
}

int fs_wrapper_write(struct fs_file *file, const void *data, size_t size)
{
	return fs_write(file->parent, data, size);
}

void fs_wrapper_write_stream(struct fs_file *file)
{
	i_assert(file->output == NULL);

	file->output = fs_write_stream(file->parent);
}

int fs_wrapper_write_stream_finish(struct fs_file *file, bool success)
{
	if (!success) {
		fs_write_stream_abort_parent(file, &file->output);
		return -1;
	}

	if (fs_write_stream_finish(file->parent, &file->output) < 0)
		return -1;
	return 1;
}

int fs_wrapper_lock(struct fs_file *file, unsigned int secs,
		    struct fs_lock **lock_r)
{
	return fs_lock(file->parent, secs, lock_r);
}

void fs_wrapper_unlock(struct fs_lock *_lock ATTR_UNUSED)
{
	i_unreached();
}

int fs_wrapper_exists(struct fs_file *file)
{
	return fs_exists(file->parent);
}

int fs_wrapper_stat(struct fs_file *file, struct stat *st_r)
{
	return fs_stat(file->parent, st_r);
}

int fs_wrapper_get_nlinks(struct fs_file *file, nlink_t *nlinks_r)
{
	return fs_get_nlinks(file->parent, nlinks_r);
}

int fs_wrapper_copy(struct fs_file *src, struct fs_file *dest)
{
	if (src != NULL)
		return fs_copy(src->parent, dest->parent);
	else
		return fs_copy_finish_async(dest->parent);
}

int fs_wrapper_rename(struct fs_file *src, struct fs_file *dest)
{
	return fs_rename(src->parent, dest->parent);
}

int fs_wrapper_delete(struct fs_file *file)
{
	return fs_delete(file->parent);
}

struct fs_iter *
fs_wrapper_iter_init(struct fs *fs, const char *path,
		     enum fs_iter_flags flags)
{
	struct wrapper_fs_iter *iter;

	iter = i_new(struct wrapper_fs_iter, 1);
	iter->iter.fs = fs;
	iter->iter.flags = flags;
	iter->parent = fs_iter_init(fs->parent, path, flags);
	return &iter->iter;
}

const char *fs_wrapper_iter_next(struct fs_iter *_iter)
{
	struct wrapper_fs_iter *iter = (struct wrapper_fs_iter *)_iter;
	const char *fname;

	iter->parent->async_callback = _iter->async_callback;
	iter->parent->async_context = _iter->async_context;

	fname = fs_iter_next(iter->parent);
	_iter->async_have_more = iter->parent->async_have_more;
	return fname;
}

int fs_wrapper_iter_deinit(struct fs_iter *_iter)
{
	struct wrapper_fs_iter *iter = (struct wrapper_fs_iter *)_iter;
	int ret;

	ret = fs_iter_deinit(&iter->parent);
	i_free(iter);
	return ret;
}
