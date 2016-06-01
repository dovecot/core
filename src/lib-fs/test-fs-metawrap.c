/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "fs-test.h"
#include "test-common.h"

static void test_fs_metawrap_stat(void)
{
	struct fs_settings fs_set;
	struct fs *fs;
	struct fs_file *file;
	struct test_fs_file *test_file;
	struct istream *input;
	struct stat st;
	const char *error;
	unsigned int i;

	test_begin("fs metawrap stat");

	memset(&fs_set, 0, sizeof(fs_set));
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

		if (input != NULL)
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

int main(void)
{
	static void (*test_functions[])(void) = {
		test_fs_metawrap_stat,
		test_fs_metawrap_async,
		NULL
	};
	return test_run(test_functions);
}
