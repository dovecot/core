/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ostream.h"
#include "fs-test.h"
#include "test-common.h"

static void test_fs_async_write(const char *test_name, struct fs *fs)
{
	struct fs_file *file;
	struct test_fs_file *test_file;
	struct ostream *output;
	unsigned int i;

	test_begin(t_strdup_printf("%s: async write", test_name));
	for (i = 0; i < 3; i++) {
		file = fs_file_init(fs, "foo", FS_OPEN_MODE_REPLACE |
				    FS_OPEN_FLAG_ASYNC);
		output = fs_write_stream(file);

		o_stream_nsend_str(output, "12345");
		if (i < 2) {
			test_assert(fs_write_stream_finish(file, &output) == 0);
			test_assert(output == NULL);
			test_assert(fs_write_stream_finish_async(file) == 0);
		}

		test_file = test_fs_file_get(fs, "foo");
		test_file->wait_async = FALSE;

		switch (i) {
		case 0:
			test_assert(fs_write_stream_finish_async(file) > 0);
			test_assert(test_file->contents->used > 0);
			break;
		case 1:
			test_file->io_failure = TRUE;
			test_assert(fs_write_stream_finish_async(file) < 0);
			test_assert(test_file->contents->used == 0);
			break;
		case 2:
			fs_write_stream_abort(file, &output);
			test_assert(test_file->contents->used == 0);
			break;
		}
		fs_file_deinit(&file);
	}
	test_end();
}

static void test_fs_async_copy(const char *test_name, struct fs *fs)
{
	struct fs_file *src, *dest;
	struct test_fs_file *test_file;

	test_begin(t_strdup_printf("%s: async copy", test_name));

	src = fs_file_init(fs, "foo", FS_OPEN_MODE_REPLACE);
	test_assert(fs_write(src, "source", 6) == 0);

	dest = fs_file_init(fs, "bar", FS_OPEN_MODE_REPLACE |
			    FS_OPEN_FLAG_ASYNC);

	test_assert(fs_copy(src, dest) == -1 && errno == EAGAIN);

	test_file = test_fs_file_get(fs, "bar");
	test_file->wait_async = FALSE;

	test_assert(fs_copy_finish_async(dest) == 0);
	test_assert(test_file->contents->used > 0);
	fs_file_deinit(&dest);

	fs_file_deinit(&src);
	test_end();
}

void test_fs_async(const char *test_name, enum fs_properties properties,
		   const char *driver, const char *args)
{
	struct fs_settings fs_set;
	struct fs *fs;
	struct test_fs *test_fs;
	const char *error;

	i_zero(&fs_set);
	if (fs_init(driver, args, &fs_set, &fs, &error) < 0)
		i_fatal("fs_init() failed: %s", error);

	test_fs = test_fs_get(fs);
	test_fs->properties = properties;

	test_fs_async_write(test_name, fs);
	test_fs_async_copy(test_name, fs);

	fs_deinit(&fs);
}
