/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "module-dir.h"
#include "str.h"
#include "istream.h"
#include "istream-seekable.h"
#include "ostream.h"
#include "fs-api-private.h"

static struct module *fs_modules = NULL;
static ARRAY(const struct fs *) fs_classes;

static int
fs_alloc(const struct fs *fs_class, const char *args,
	 const struct fs_settings *set, struct fs **fs_r, const char **error_r)
{
	struct fs *fs;
	int ret;

	fs = fs_class->v.alloc();
	fs->last_error = str_new(default_pool, 64);

	T_BEGIN {
		ret = fs_class->v.init(fs, args, set);
	} T_END;
	if (ret < 0) {
		/* a bit kludgy way to allow data stack frame usage in normal
		   conditions but still be able to return error message from
		   data stack. */
		*error_r = t_strdup_printf("%s: %s", fs_class->name,
					   fs_last_error(fs));
		fs_deinit(&fs);
		return -1;
	}
	*fs_r = fs;
	return 0;
}

static void fs_class_register(const struct fs *fs_class)
{
	array_append(&fs_classes, &fs_class, 1);
}

static void fs_classes_deinit(void)
{
	array_free(&fs_classes);
}

static void fs_classes_init(void)
{
	i_array_init(&fs_classes, 8);
	fs_class_register(&fs_class_posix);
	fs_class_register(&fs_class_metawrap);
	fs_class_register(&fs_class_sis);
	fs_class_register(&fs_class_sis_queue);
	lib_atexit(fs_classes_deinit);
}

static const struct fs *fs_class_find(const char *driver)
{
	const struct fs *const *classp;

	if (!array_is_created(&fs_classes))
		fs_classes_init();

	array_foreach(&fs_classes, classp) {
		if (strcmp((*classp)->name, driver) == 0)
			return *classp;
	}
	return NULL;
}

static void fs_class_deinit_modules(void)
{
	module_dir_unload(&fs_modules);
}

static void fs_class_try_load_plugin(const char *driver)
{
	const char *module_name = t_strdup_printf("fs_%s", driver);
	struct module *module;
	struct module_dir_load_settings mod_set;
	const struct fs *fs_class;

	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.ignore_missing = TRUE;

	fs_modules = module_dir_load_missing(fs_modules, MODULE_DIR,
					     module_name, &mod_set);
	module_dir_init(fs_modules);

	module = module_dir_find(fs_modules, module_name);
	fs_class = module == NULL ? NULL :
		module_get_symbol(module, t_strdup_printf("fs_class_%s", driver));
	if (fs_class != NULL)
		fs_class_register(fs_class);

	lib_atexit(fs_class_deinit_modules);
}

int fs_init(const char *driver, const char *args,
	    const struct fs_settings *set,
	    struct fs **fs_r, const char **error_r)
{
	const struct fs *fs_class;
	const char *temp_file_prefix;

	fs_class = fs_class_find(driver);
	if (fs_class == NULL) {
		T_BEGIN {
			fs_class_try_load_plugin(driver);
		} T_END;
		fs_class = fs_class_find(driver);
	}
	if (fs_class == NULL) {
		*error_r = t_strdup_printf("Unknown fs driver: %s", driver);
		return -1;
	}
	if (fs_alloc(fs_class, args, set, fs_r, error_r) < 0)
		return -1;

	temp_file_prefix = set->temp_file_prefix != NULL ?
		set->temp_file_prefix : ".temp.dovecot";
	(*fs_r)->temp_path_prefix = i_strconcat(set->temp_dir, "/",
						temp_file_prefix, NULL);
	return 0;
}

void fs_deinit(struct fs **_fs)
{
	struct fs *fs = *_fs;
	string_t *last_error = fs->last_error;

	*_fs = NULL;

	if (fs->files_open_count > 0) {
		i_panic("fs-%s: %u files still open",
			fs->name, fs->files_open_count);
	}

	i_free(fs->temp_path_prefix);
	fs->v.deinit(fs);
	str_free(&last_error);
}

const char *fs_get_root_driver(struct fs *fs)
{
	while (fs->parent != NULL)
		fs = fs->parent;
	return fs->name;
}

struct fs_file *fs_file_init(struct fs *fs, const char *path, int mode_flags)
{
	struct fs_file *file;

	i_assert(path != NULL);

	T_BEGIN {
		file = fs->v.file_init(fs, path, mode_flags & FS_OPEN_MODE_MASK,
				       mode_flags & ~FS_OPEN_MODE_MASK);
	} T_END;
	file->flags = mode_flags & ~FS_OPEN_MODE_MASK;
	fs->files_open_count++;
	return file;
}

void fs_file_deinit(struct fs_file **_file)
{
	struct fs_file *file = *_file;
	pool_t metadata_pool = file->metadata_pool;

	i_assert(file->fs->files_open_count > 0);

	*_file = NULL;

	fs_file_close(file);

	file->fs->files_open_count--;
	T_BEGIN {
		file->fs->v.file_deinit(file);
	} T_END;

	if (metadata_pool != NULL)
		pool_unref(&metadata_pool);
}

void fs_file_close(struct fs_file *file)
{
	if (file->pending_read_input != NULL)
		i_stream_unref(&file->pending_read_input);
	if (file->seekable_input != NULL)
		i_stream_unref(&file->seekable_input);

	if (file->copy_input != NULL) {
		i_stream_unref(&file->copy_input);
		(void)fs_write_stream_abort(file, &file->copy_output);
	}
	if (file->fs->v.file_close != NULL) T_BEGIN {
		file->fs->v.file_close(file);
	} T_END;
}

enum fs_properties fs_get_properties(struct fs *fs)
{
	return fs->v.get_properties(fs);
}

void fs_metadata_init(struct fs_file *file)
{
	if (file->metadata_pool == NULL) {
		file->metadata_pool = pool_alloconly_create("fs metadata", 1024);
		p_array_init(&file->metadata, file->metadata_pool, 8);
	}
}

void fs_default_set_metadata(struct fs_file *file,
			     const char *key, const char *value)
{
	struct fs_metadata *metadata;

	fs_metadata_init(file);
	metadata = array_append_space(&file->metadata);
	metadata->key = p_strdup(file->metadata_pool, key);
	metadata->value = p_strdup(file->metadata_pool, value);
}

void fs_set_metadata(struct fs_file *file, const char *key, const char *value)
{
	if (file->fs->v.set_metadata != NULL) T_BEGIN {
		file->fs->v.set_metadata(file, key, value);
	} T_END;
}

int fs_get_metadata(struct fs_file *file,
		    const ARRAY_TYPE(fs_metadata) **metadata_r)
{
	if (file->fs->v.get_metadata == NULL) {
		fs_set_error(file->fs, "Metadata not supported by backend");
		return -1;
	}
	return file->fs->v.get_metadata(file, metadata_r);
}

const char *fs_file_path(struct fs_file *file)
{
	return file->fs->v.get_path == NULL ? file->path :
		file->fs->v.get_path(file);
}

static void ATTR_FORMAT(2, 0)
fs_set_verror(struct fs *fs, const char *fmt, va_list args)
{
	/* the error is always kept in the parentmost fs */
	if (fs->parent != NULL)
		fs_set_verror(fs->parent, fmt, args);
	else {
		str_truncate(fs->last_error, 0);
		str_vprintfa(fs->last_error, fmt, args);
	}
}

const char *fs_last_error(struct fs *fs)
{
	/* the error is always kept in the parentmost fs */
	if (fs->parent != NULL)
		return fs_last_error(fs->parent);

	if (str_len(fs->last_error) == 0)
		return "BUG: Unknown fs error";
	return str_c(fs->last_error);
}

const char *fs_file_last_error(struct fs_file *file)
{
	return fs_last_error(file->fs);
}

bool fs_prefetch(struct fs_file *file, uoff_t length)
{
	bool ret;

	T_BEGIN {
		ret = file->fs->v.prefetch(file, length);
	} T_END;
	return ret;
}

ssize_t fs_read_via_stream(struct fs_file *file, void *buf, size_t size)
{
	const unsigned char *data;
	size_t data_size;
	ssize_t ret;

	i_assert(size > 0);

	if (file->pending_read_input == NULL)
		file->pending_read_input = fs_read_stream(file, size+1);
	ret = i_stream_read_data(file->pending_read_input,
				 &data, &data_size, size-1);
	if (ret == 0) {
		fs_set_error_async(file->fs);
		return -1;
	}
	if (ret < 0 && file->pending_read_input->stream_errno != 0) {
		fs_set_error(file->fs, "read(%s) failed: %m",
			     i_stream_get_name(file->pending_read_input));
	} else {
		ret = I_MIN(size, data_size);
		memcpy(buf, data, ret);
	}
	i_stream_unref(&file->pending_read_input);
	return ret;
}

ssize_t fs_read(struct fs_file *file, void *buf, size_t size)
{
	int ret;

	if (file->fs->v.read != NULL) {
		T_BEGIN {
			ret = file->fs->v.read(file, buf, size);
		} T_END;
		return ret;
	}

	/* backend didn't bother to implement read(), but we can do it with
	   streams. */
	return fs_read_via_stream(file, buf, size);
}

struct istream *fs_read_stream(struct fs_file *file, size_t max_buffer_size)
{
	struct istream *input, *inputs[2];
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	bool want_seekable = FALSE;

	if (file->seekable_input != NULL) {
		i_stream_seek(file->seekable_input, 0);
		i_stream_ref(file->seekable_input);
		return file->seekable_input;
	}
	T_BEGIN {
		input = file->fs->v.read_stream(file, max_buffer_size);
	} T_END;
	if (input->stream_errno != 0) {
		/* read failed already */
		return input;
	}

	if ((file->flags & FS_OPEN_FLAG_SEEKABLE) != 0)
		want_seekable = TRUE;
	else if ((file->flags & FS_OPEN_FLAG_ASYNC) == 0 && !input->blocking)
		want_seekable = TRUE;

	if (want_seekable && !input->seekable) {
		/* need to make the stream seekable */
		inputs[0] = input;
		inputs[1] = NULL;
		input = i_stream_create_seekable_path(inputs, max_buffer_size,
						file->fs->temp_path_prefix);
		i_stream_set_name(input, i_stream_get_name(inputs[0]));
		i_stream_unref(&inputs[0]);

		file->seekable_input = input;
		i_stream_ref(file->seekable_input);
	}
	if ((file->flags & FS_OPEN_FLAG_ASYNC) == 0 && !input->blocking) {
		/* read the whole input stream before returning */
		while ((ret = i_stream_read_data(input, &data, &size, 0)) >= 0) {
			i_stream_skip(input, size);
			if (ret == 0) {
				if (fs_wait_async(file->fs) < 0) {
					input->stream_errno = errno;
					input->eof = TRUE;
					break;
				}
			}
		}
		i_stream_seek(input, 0);
	}
	return input;
}

int fs_write_via_stream(struct fs_file *file, const void *data, size_t size)
{
	struct ostream *output;
	ssize_t ret;
	int err;

	if (!file->write_pending) {
		output = fs_write_stream(file);
		if ((ret = o_stream_send(output, data, size)) < 0) {
			err = errno;
			fs_set_error(file->fs, "fs_write(%s) failed: %m",
				     o_stream_get_name(output));
			fs_write_stream_abort(file, &output);
			errno = err;
			return -1;
		}
		i_assert((size_t)ret == size);
		ret = fs_write_stream_finish(file, &output);
	} else {
		ret = fs_write_stream_finish_async(file);
	}
	if (ret == 0) {
		fs_set_error_async(file->fs);
		file->write_pending = TRUE;
		return -1;
	}
	file->write_pending = FALSE;
	return ret < 0 ? -1 : 0;
}

int fs_write(struct fs_file *file, const void *data, size_t size)
{
	int ret;

	if (file->fs->v.write != NULL) {
		T_BEGIN {
			ret = file->fs->v.write(file, data, size);
		} T_END;
		return ret;
	}

	/* backend didn't bother to implement write(), but we can do it with
	   streams. */
	return fs_write_via_stream(file, data, size);
}

struct ostream *fs_write_stream(struct fs_file *file)
{
	T_BEGIN {
		file->fs->v.write_stream(file);
	} T_END;
	i_assert(file->output != NULL);
	return file->output;
}

int fs_write_stream_finish(struct fs_file *file, struct ostream **output)
{
	int ret;

	i_assert(*output == file->output || *output == NULL);

	*output = NULL;
	T_BEGIN {
		ret = file->fs->v.write_stream_finish(file, TRUE);
	} T_END;
	return ret;
}

int fs_write_stream_finish_async(struct fs_file *file)
{
	int ret;

	T_BEGIN {
		ret = file->fs->v.write_stream_finish(file, TRUE);
	} T_END;
	return ret;
}

void fs_write_stream_abort(struct fs_file *file, struct ostream **output)
{
	i_assert(*output == file->output);

	*output = NULL;
	T_BEGIN {
		(void)file->fs->v.write_stream_finish(file, FALSE);
	} T_END;
}

void fs_file_set_async_callback(struct fs_file *file,
				fs_file_async_callback_t *callback,
				void *context)
{
	if (file->fs->v.set_async_callback != NULL)
		file->fs->v.set_async_callback(file, callback, context);
	else
		callback(context);
}

int fs_wait_async(struct fs *fs)
{
	int ret;

	if (fs->v.wait_async == NULL)
		ret = 0;
	else T_BEGIN {
		ret = fs->v.wait_async(fs);
	} T_END;
	return ret;
}

int fs_lock(struct fs_file *file, unsigned int secs, struct fs_lock **lock_r)
{
	int ret;

	T_BEGIN {
		ret = file->fs->v.lock(file, secs, lock_r);
	} T_END;
	return ret;
}

void fs_unlock(struct fs_lock **_lock)
{
	struct fs_lock *lock = *_lock;

	*_lock = NULL;
	T_BEGIN {
		lock->file->fs->v.unlock(lock);
	} T_END;
}

int fs_exists(struct fs_file *file)
{
	int ret;

	T_BEGIN {
		ret = file->fs->v.exists(file);
	} T_END;
	return ret;
}

int fs_stat(struct fs_file *file, struct stat *st_r)
{
	int ret;

	T_BEGIN {
		ret = file->fs->v.stat(file, st_r);
	} T_END;
	return ret;
}

int fs_default_copy(struct fs_file *src, struct fs_file *dest)
{
	if (dest->copy_src != NULL) {
		i_assert(src == NULL || src == dest->copy_src);
		if (dest->copy_output == NULL) {
			i_assert(dest->copy_input == NULL);
			if (fs_write_stream_finish_async(dest) <= 0)
				return -1;
			dest->copy_src = NULL;
			return 0;
		}
	} else {
		dest->copy_src = src;
		dest->copy_input = fs_read_stream(src, IO_BLOCK_SIZE);
		dest->copy_output = fs_write_stream(dest);
	}
	while (o_stream_send_istream(dest->copy_output, dest->copy_input) > 0) ;
	if (dest->copy_input->stream_errno != 0) {
		errno = dest->copy_input->stream_errno;
		fs_set_error(dest->fs, "read(%s) failed: %m",
			     i_stream_get_name(dest->copy_input));
		i_stream_unref(&dest->copy_input);
		fs_write_stream_abort(dest, &dest->copy_output);
		return -1;
	}
	if (dest->copy_output->stream_errno != 0) {
		errno = dest->copy_output->stream_errno;
		fs_set_error(dest->fs, "write(%s) failed: %m",
			     o_stream_get_name(dest->copy_output));
		i_stream_unref(&dest->copy_input);
		fs_write_stream_abort(dest, &dest->copy_output);
		return -1;
	}
	if (!dest->copy_input->eof) {
		fs_set_error_async(dest->fs);
		return -1;
	}
	i_stream_unref(&dest->copy_input);
	if (fs_write_stream_finish(dest, &dest->copy_output) <= 0)
		return -1;
	dest->copy_src = NULL;
	return 0;
}

int fs_copy(struct fs_file *src, struct fs_file *dest)
{
	int ret;

	i_assert(src->fs == dest->fs);

	T_BEGIN {
		ret = src->fs->v.copy(src, dest);
	} T_END;
	return ret;
}

int fs_copy_finish_async(struct fs_file *dest)
{
	int ret;

	T_BEGIN {
		ret = dest->fs->v.copy(NULL, dest);
	} T_END;
	return ret;
}

int fs_rename(struct fs_file *src, struct fs_file *dest)
{
	int ret;

	i_assert(src->fs == dest->fs);

	T_BEGIN {
		ret = src->fs->v.rename(src, dest);
	} T_END;
	return ret;
}

int fs_delete(struct fs_file *file)
{
	int ret;

	T_BEGIN {
		ret = file->fs->v.delete_file(file);
	} T_END;
	return ret;
}

struct fs_iter *
fs_iter_init(struct fs *fs, const char *path, enum fs_iter_flags flags)
{
	struct fs_iter *iter;

	T_BEGIN {
		iter = fs->v.iter_init(fs, path, flags);
	} T_END;
	return iter;
}

int fs_iter_deinit(struct fs_iter **_iter)
{
	struct fs_iter *iter = *_iter;
	int ret;

	*_iter = NULL;
	T_BEGIN {
		ret = iter->fs->v.iter_deinit(iter);
	} T_END;
	return ret;
}

const char *fs_iter_next(struct fs_iter *iter)
{
	return iter->fs->v.iter_next(iter);
}

void fs_set_error(struct fs *fs, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fs_set_verror(fs, fmt, args);
	va_end(args);
}

void fs_set_critical(struct fs *fs, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fs_set_verror(fs, fmt, args);

	i_error("fs-%s: %s", fs->name, fs_last_error(fs));
	va_end(args);
}

void fs_set_error_async(struct fs *fs)
{
	fs_set_error(fs, "Asynchronous operation in progress");
	errno = EAGAIN;
}
