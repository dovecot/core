/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream-cmp.h"
#include "fs-sis-common.h"

struct sis_fs {
	struct fs fs;
	struct fs *super;
};

struct sis_fs_file {
	struct fs_file file;
	struct fs_file *super;
	enum fs_open_mode open_mode;

	struct fs_file *hash_file;
	struct istream *hash_input;
	struct ostream *fs_output;

	char *hash, *hash_path;
};

static void fs_sis_copy_error(struct sis_fs *fs)
{
	fs_set_error(&fs->fs, "%s", fs_last_error(fs->super));
}

static void fs_sis_file_copy_error(struct sis_fs_file *file)
{
	struct sis_fs *fs = (struct sis_fs *)file->file.fs;

	fs_sis_copy_error(fs);
}

static struct fs *
fs_sis_init(const char *args, const struct fs_settings *set)
{
	struct sis_fs *fs;
	const char *p;

	fs = i_new(struct sis_fs, 1);
	fs->fs = fs_class_sis;

	if (*args == '\0')
		i_fatal("fs-sis: Parent filesystem not given as parameter");

	p = strchr(args, ':');
	if (p == NULL)
		fs->super = fs_init(args, "", set);
	else
		fs->super = fs_init(t_strdup_until(args, p), p+1, set);
	return &fs->fs;
}

static void fs_sis_deinit(struct fs *_fs)
{
	struct sis_fs *fs = (struct sis_fs *)_fs;

	fs_deinit(&fs->super);
	i_free(fs);
}

static int
fs_sis_open(struct fs *_fs, const char *path, enum fs_open_mode mode,
	    enum fs_open_flags flags, struct fs_file **file_r)
{
	struct sis_fs *fs = (struct sis_fs *)_fs;
	struct sis_fs_file *file;
	struct fs_file *super;
	const char *dir, *hash;

	if (mode == FS_OPEN_MODE_APPEND) {
		fs_set_error(_fs, "APPEND mode not supported");
		return -1;
	}

	if (fs_open(fs->super, path, mode | flags, &super) < 0) {
		fs_sis_copy_error(fs);
		return -1;
	}

	switch (mode) {
	case FS_OPEN_MODE_RDONLY:
		*file_r = super;
		return 0;
	case FS_OPEN_MODE_CREATE:
	case FS_OPEN_MODE_REPLACE:
		break;
	case FS_OPEN_MODE_APPEND:
		i_unreached();
	}

	if (fs_sis_path_parse(_fs, path, &dir, &hash) < 0)
		return -1;

	file = i_new(struct sis_fs_file, 1);
	file->file.fs = _fs;
	file->file.path = i_strdup(fs_file_path(super));
	file->super = super;
	file->open_mode = mode;
	file->hash = i_strdup(hash);

	/* if hashes/<hash> already exists, open it */
	file->hash_path = i_strdup_printf("%s/"HASH_DIR_NAME"/%s", dir, hash);
	if (fs_open(fs->super, file->hash_path, FS_OPEN_MODE_RDONLY,
		    &file->hash_file) < 0 && errno != ENOENT) {
		i_error("fs-sis: Couldn't open hash file: %s",
			fs_last_error(fs->super));
	}
	if (file->hash_file != NULL) {
		file->hash_input =
			fs_read_stream(file->hash_file, IO_BLOCK_SIZE);
	}

	*file_r = &file->file;
	return 0;
}

static void fs_sis_close(struct fs_file *_file)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	if (file->hash_file != NULL) {
		i_stream_unref(&file->hash_input);
		fs_close(&file->hash_file);
	}
	fs_close(&file->super);
	i_free(file->hash);
	i_free(file->hash_path);
	i_free(file->file.path);
	i_free(file);
}

static ssize_t fs_sis_read(struct fs_file *_file, void *buf, size_t size)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;
	ssize_t ret;

	if ((ret = fs_read(file->super, buf, size)) < 0)
		fs_sis_file_copy_error(file);
	return ret;
}

static struct istream *
fs_sis_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	return fs_read_stream(file->super, max_buffer_size);
}

static bool fs_sis_try_link(struct sis_fs_file *file)
{
	const char *path = fs_file_path(&file->file);
	const struct stat *st;
	struct stat st2;

	st = i_stream_stat(file->hash_input, FALSE);

	/* we can use the existing file */
	if (fs_link(file->super->fs, file->hash_path, path) < 0) {
		if (errno != ENOENT && errno != EMLINK)
			i_error("fs-sis: %s", fs_last_error(file->super->fs));
		/* failed to use link(), continue as if it hadn't been equal */
		return FALSE;
	}
	if (fs_stat(file->super->fs, path, &st2) < 0) {
		i_error("fs-sis: %s", fs_last_error(file->super->fs));
		if (fs_unlink(file->super->fs, path) < 0)
			i_error("fs-sis: %s", fs_last_error(file->super->fs));
		return FALSE;
	}
	if (st->st_ino != st2.st_ino) {
		/* the hashes/ file was already replaced with something else */
		if (fs_unlink(file->super->fs, path) < 0)
			i_error("fs-sis: %s", fs_last_error(file->super->fs));
		return FALSE;
	}
	return TRUE;
}

static void fs_sis_replace_hash_file(struct sis_fs_file *file)
{
	const char *hash_fname, *path = fs_file_path(&file->file);
	struct fs *super_fs = file->super->fs;
	string_t *temp_path;
	int ret;

	if (file->hash_input == NULL) {
		/* hash file didn't exist previously. we should be able to
		   create it with link() */
		if (fs_link(super_fs, path, file->hash_path) < 0) {
			if (errno == EEXIST) {
				/* the file was just created. it's probably
				   a duplicate, but it's too much trouble
				   trying to deduplicate it anymore */
			} else {
				i_error("fs-sis: %s", fs_last_error(super_fs));
			}
		}
		return;
	}

	temp_path = t_str_new(256);
	hash_fname = strrchr(file->hash_path, '/');
	if (hash_fname == NULL)
		hash_fname = file->hash_path;
	else {
		str_append_n(temp_path, file->hash_path,
			     (hash_fname-file->hash_path) + 1);
		hash_fname++;
	}
	str_printfa(temp_path, "%s%s.tmp",
		    super_fs->set.temp_file_prefix, hash_fname);

	/* replace existing hash file atomically */
	ret = fs_link(super_fs, path, str_c(temp_path));
	if (ret < 0 && errno == EEXIST) {
		/* either someone's racing us or it's a stale file.
		   try to continue. */
		if (fs_unlink(super_fs, str_c(temp_path)) < 0 &&
		    errno != ENOENT)
			i_error("fs-sis: %s", fs_last_error(super_fs));
		ret = fs_link(super_fs, path, str_c(temp_path));
	}
	if (ret < 0) {
		i_error("fs-sis: %s", fs_last_error(super_fs));
		return;
	}
	if (fs_rename(super_fs, str_c(temp_path), file->hash_path) < 0) {
		if (errno == ENOENT) {
			/* apparently someone else just renamed it. ignore. */
		} else {
			i_error("fs-sis: %s", fs_last_error(super_fs));
		}
		(void)fs_unlink(super_fs, str_c(temp_path));
	}
}

static int fs_sis_write(struct fs_file *_file, const void *data, size_t size)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	if (file->hash_input != NULL &&
	    stream_cmp_block(file->hash_input, data, size) &&
	    i_stream_is_eof(file->hash_input)) {
		/* try to use existing file */
		if (fs_sis_try_link(file))
			return 0;
	}

	if (fs_write(file->super, data, size) < 0) {
		fs_sis_file_copy_error(file);
		return -1;
	}
	T_BEGIN {
		fs_sis_replace_hash_file(file);
	} T_END;
	return 0;
}

static void fs_sis_write_stream(struct fs_file *_file)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	i_assert(_file->output == NULL);

	file->fs_output = fs_write_stream(file->super);
	if (file->hash_input == NULL)
		_file->output = file->fs_output;
	else {
		/* compare if files are equal */
		_file->output = o_stream_create_cmp(file->fs_output,
						    file->hash_input);
	}
}

static int fs_sis_write_stream_finish(struct fs_file *_file, bool success)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	if (!success) {
		fs_write_stream_abort(file->super, &file->fs_output);
		fs_sis_file_copy_error(file);
		return -1;
	}

	if (file->hash_input != NULL &&
	    o_stream_cmp_equals(_file->output) &&
	    i_stream_is_eof(file->hash_input)) {
		if (fs_sis_try_link(file)) {
			fs_write_stream_abort(file->super, &file->fs_output);
			return 0;
		}
	}

	if (fs_write_stream_finish(file->super, &file->fs_output) < 0) {
		fs_sis_file_copy_error(file);
		return -1;
	}
	T_BEGIN {
		fs_sis_replace_hash_file(file);
	} T_END;
	return 0;
}

static int
fs_sis_lock(struct fs_file *_file, unsigned int secs, struct fs_lock **lock_r)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	if (fs_lock(file->super, secs, lock_r) < 0) {
		fs_sis_file_copy_error(file);
		return -1;
	}
	return 0;
}

static void fs_sis_unlock(struct fs_lock *_lock ATTR_UNUSED)
{
	i_unreached();
}

static int fs_sis_fdatasync(struct fs_file *_file)
{
	struct sis_fs_file *file = (struct sis_fs_file *)_file;

	if (fs_fdatasync(file->super) < 0) {
		fs_sis_file_copy_error(file);
		return -1;
	}
	return 0;
}

static int fs_sis_exists(struct fs *_fs, const char *path)
{
	struct sis_fs *fs = (struct sis_fs *)_fs;

	if (fs_exists(fs->super, path) < 0) {
		fs_sis_copy_error(fs);
		return -1;
	}
	return 0;
}

static int fs_sis_stat(struct fs *_fs, const char *path, struct stat *st_r)
{
	struct sis_fs *fs = (struct sis_fs *)_fs;

	if (fs_stat(fs->super, path, st_r) < 0) {
		fs_sis_copy_error(fs);
		return -1;
	}
	return 0;
}

static int fs_sis_link(struct fs *_fs, const char *src, const char *dest)
{
	struct sis_fs *fs = (struct sis_fs *)_fs;

	if (fs_link(fs->super, src, dest) < 0) {
		fs_sis_copy_error(fs);
		return -1;
	}
	return 0;
}

static int fs_sis_rename(struct fs *_fs, const char *src, const char *dest)
{
	struct sis_fs *fs = (struct sis_fs *)_fs;

	if (fs_rename(fs->super, src, dest) < 0) {
		fs_sis_copy_error(fs);
		return -1;
	}
	return 0;
}

static int fs_sis_unlink(struct fs *_fs, const char *path)
{
	struct sis_fs *fs = (struct sis_fs *)_fs;

	T_BEGIN {
		fs_sis_try_unlink_hash_file(&fs->fs, fs->super, path);
	} T_END;
	if (fs_unlink(fs->super, path) < 0) {
		fs_sis_copy_error(fs);
		return -1;
	}
	return 0;
}

static int fs_sis_rmdir(struct fs *_fs, const char *path)
{
	struct sis_fs *fs = (struct sis_fs *)_fs;

	if (fs_rmdir(fs->super, path) < 0) {
		fs_sis_copy_error(fs);
		return -1;
	}
	return 0;
}

struct fs fs_class_sis = {
	.name = "sis",
	.v = {
		fs_sis_init,
		fs_sis_deinit,
		fs_sis_open,
		fs_sis_close,
		fs_sis_read,
		fs_sis_read_stream,
		fs_sis_write,
		fs_sis_write_stream,
		fs_sis_write_stream_finish,
		fs_sis_lock,
		fs_sis_unlock,
		fs_sis_fdatasync,
		fs_sis_exists,
		fs_sis_stat,
		fs_sis_link,
		fs_sis_rename,
		fs_sis_unlink,
		fs_sis_rmdir
	}
};
