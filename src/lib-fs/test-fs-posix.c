/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ostream.h"
#include "fs-api.h"
#include "safe-mkdir.h"
#include "safe-mkstemp.h"
#include "test-common.h"
#include "unlink-directory.h"
#include <sys/stat.h>
#include <unistd.h>

static void test_fs_posix(void)
{
	const char testdir[] = ".test-fs-posix";
	const char *unlink_err;

	if (unlink_directory(testdir, UNLINK_DIRECTORY_FLAG_RMDIR, &unlink_err) < 0) {
		i_error("Couldn't prepare test directory (%s): %s", testdir, unlink_err);
		goto error_no_testdir;
	}
	if (safe_mkdir(testdir, 0700, (uid_t)-1, (gid_t)-1) != 1) {
		/* Something just raced us to create this directory, bail. */
		goto error_no_testdir;
	}

	int ret;
	const char *error;
	struct fs *fs;
	struct fs_settings fs_set;

	test_begin("test-fs-posix filesystem");
	i_zero(&fs_set);
	ret = fs_init("posix", t_strdup_printf("prefix=%s/", testdir), &fs_set, &fs, &error);
	test_out_quiet("fs_init() failed", ret >= 0);
	if (ret < 0) {
		test_end();
		goto error_no_fs;
	}

	struct fs *ref = fs;
	fs_ref(ref);
	fs_unref(&ref);
	test_assert(ref == NULL);
	test_assert(fs != NULL);

	test_assert(fs_get_parent(fs) == NULL);
	test_assert_strcmp(fs_get_driver(fs), "posix");
	test_end();

	struct fs_file *file;
	char buf[10];
	ssize_t count;
	test_begin("test-fs-posix bad file read");
	file = fs_file_init(fs, "fail_1", FS_OPEN_MODE_READONLY);
	test_assert(fs_exists(file) == 0);
	count = fs_read(file, buf, 1);
	test_assert(count == -1 && errno == ENOENT);
	fs_file_deinit(&file);
	test_end();

	test_begin("test-fs-posix good file write");
	file = fs_file_init(fs, "good1", FS_OPEN_MODE_REPLACE);
	test_assert(file != NULL);
	test_assert(fs_exists(file) == 0); /* file not created until data is written */
	test_assert(fs_write(file, "X", 1) == 0);
	test_assert(fs_exists(file) == 1);
	fs_file_deinit(&file);
	test_end();

	test_begin("test-fs-posix good file read");
	file = fs_file_init(fs, "good1", FS_OPEN_MODE_READONLY);
	test_assert(fs_exists(file) == 1);
	errno = 0;
	count = fs_read(file, buf, 2);
	test_assert(count == 1 && errno == 0);
	fs_file_deinit(&file);
	test_end();

	struct fs_iter *iter = fs_iter_init(fs, "/", 0);
	const char *filename;
	test_begin("test-fs-posix iterator");
	filename = fs_iter_next(iter);
	test_assert_strcmp(filename, "good1");
	test_assert(fs_iter_next(iter) == NULL);
	fs_iter_deinit(&iter);
	test_end();

	struct stat st;
	test_begin("test-fs-posix file stat and delete");
	file = fs_file_init(fs, "good1", FS_OPEN_MODE_READONLY);
	test_assert(fs_stat(file, &st) == 0);
	test_assert(st.st_size == 1);
	test_assert(fs_delete(file) == 0);
	fs_file_deinit(&file);
	test_end();

	test_begin("test-fs-posix file write fname rename");
	file = fs_file_init(fs, "subdir/badfname", FS_OPEN_MODE_REPLACE);
	struct ostream *output = fs_write_stream(file);
	o_stream_nsend_str(output, "hello");
	fs_set_metadata(file, FS_METADATA_WRITE_FNAME, "subdir/rename1");
	test_assert(fs_write_stream_finish(file, &output) == 1);
	test_assert(strcmp(fs_file_path(file), "subdir/rename1") == 0);
	fs_file_deinit(&file);
	file = fs_file_init(fs, "subdir/rename1", FS_OPEN_MODE_READONLY);
	test_assert(fs_stat(file, &st) == 0);
	test_assert(st.st_size == 5);
	fs_file_deinit(&file);
	test_end();

	test_begin("test-fs-posix file copy fname rename");
	struct fs_file *src = fs_file_init(fs, "subdir/rename1", FS_OPEN_MODE_READONLY);
	struct fs_file *dest = fs_file_init(fs, "subdir/badfname", FS_OPEN_MODE_REPLACE);
	fs_set_metadata(dest, FS_METADATA_WRITE_FNAME, "subdir/rename2");
	test_assert(fs_copy(src, dest) == 0);
	test_assert(strcmp(fs_file_path(dest), "subdir/rename2") == 0);
	fs_file_deinit(&src);
	fs_file_deinit(&dest);
	file = fs_file_init(fs, "subdir/rename2", FS_OPEN_MODE_READONLY);
	test_assert(fs_stat(file, &st) == 0);
	test_assert(st.st_size == 5);
	fs_file_deinit(&file);
	test_end();

	fs_deinit(&fs);

error_no_fs:
	if (unlink_directory(testdir, UNLINK_DIRECTORY_FLAG_RMDIR, &unlink_err) < 0)
		i_error("Couldn't clean up test directory (%s): %s", testdir, unlink_err);
error_no_testdir:
	return;
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_fs_posix,
		NULL
	};
	return test_run(test_functions);
}
