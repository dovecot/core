/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "fs-test.h"
#include "test-common.h"

static const struct fs_settings fs_set;

static void test_fs_metawrap_stat(void)
{
	struct fs *fs;
	struct fs_file *file;
	struct test_fs_file *test_file;
	struct istream *input;
	struct stat st;
	const char *error;
	unsigned int i;

	test_begin("fs metawrap stat");

	if (fs_init("metawrap", "test", &fs_set, &fs, &error) < 0)
		i_fatal("fs_init() failed: %s", error);

	for (i = 0; i < 2; i++) {
		file = fs_file_init(fs, "foo", FS_OPEN_MODE_READONLY);

		test_file = test_fs_file_get(fs, "foo");
		str_append(test_file->contents, "key:value\n\n12345678901234567890");

		if (i == 0) {
			input = fs_read_stream(file, 2);
			test_istream_set_max_buffer_size(test_file->input, 2);
		} else {
			input = NULL;
		}

		test_assert_idx(fs_stat(file, &st) == 0 && st.st_size == 20, i);

		i_stream_unref(&input);
		fs_file_deinit(&file);
	}
	fs_deinit(&fs);
	test_end();
}

static void test_fs_metawrap_async(void)
{
	test_fs_async("metawrap", FS_PROPERTY_METADATA, "metawrap", "test");
	test_fs_async("metawrap passthrough", 0, "metawrap", "test");
	test_fs_async("double-metawrap", FS_PROPERTY_METADATA, "metawrap", "metawrap:test");
}

static void test_fs_metawrap_write_empty(void)
{
	struct fs *fs;
	const char *error;

	test_begin("fs metawrap write empty file");
	if (fs_init("metawrap", "test", &fs_set, &fs, &error) < 0)
		i_fatal("fs_init() failed: %s", error);
	struct fs_file *file = fs_file_init(fs, "foo", FS_OPEN_MODE_REPLACE);
	struct ostream *output = fs_write_stream(file);
	test_assert(fs_write_stream_finish(file, &output) > 0);
	fs_file_deinit(&file);
	fs_deinit(&fs);
	test_end();
}

static void test_fs_metawrap_write_fname_rename(void)
{
	struct fs *fs;
	const char *error;

	test_begin("fs metawrap write fname rename");
	if (fs_init("metawrap", "test", &fs_set, &fs, &error) < 0)
		i_fatal("fs_init() failed: %s", error);
	struct fs_file *file = fs_file_init(fs, "foo", FS_OPEN_MODE_REPLACE);
	struct ostream *output = fs_write_stream(file);
	o_stream_nsend_str(output, "test");
	fs_set_metadata(file, FS_METADATA_WRITE_FNAME, "renamed");
	test_assert(fs_write_stream_finish(file, &output) > 0);
	test_assert(strcmp(fs_file_path(file), "renamed") == 0);
	fs_file_deinit(&file);
	fs_deinit(&fs);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_fs_metawrap_stat,
		test_fs_metawrap_async,
		test_fs_metawrap_write_empty,
		test_fs_metawrap_write_fname_rename,
		NULL
	};
	return test_run(test_functions);
}
