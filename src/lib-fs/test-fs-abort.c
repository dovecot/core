#include "lib.h"
#include "ostream.h"
#include "fs-api.h"
#include "fs-api-private.h"
#include "test-common.h"
#include "settings.h"

static void test_fs_abort(void)
{
	int ret;
	const char *error;
	struct fs *fs;
	struct fs_parameters fs_params;
	struct fs_file *file;
	struct ostream *output;

	test_begin("test-fs-abort");
	i_zero(&fs_params);

	const char *const settings[] = {
		"fs", "test",
		"fs/test/fs_driver", "test",
		NULL
	};
	struct settings_simple test_set;
	settings_simple_init(&test_set, settings);
	ret = fs_init_auto(test_set.event, &fs_params, &fs, &error);
	if (ret <= 0) {
		test_out_reason("fs_init", FALSE, error);
		test_assert(FALSE);
		return;
	}

	file = fs_file_init(fs, "abort_test", FS_OPEN_MODE_REPLACE);
	test_assert(file != NULL);

	output = fs_write_stream(file);
	test_assert(file->output != NULL);
	test_assert(output == file->output);

	/* This should trigger the assertion in fs-api.c */
	fs_write_stream_abort_error(file, &file->output, "Simulated error");

	test_assert(file->output == NULL);

	fs_file_deinit(&file);
	fs_deinit(&fs);
	settings_simple_deinit(&test_set);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_fs_abort,
		NULL
	};
	return test_run(test_functions);
}
