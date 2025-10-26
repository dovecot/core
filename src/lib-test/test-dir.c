/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "unlink-directory.h"
#include "test-private.h"
#include "test-dir.h"

#include <sys/stat.h>

static char *test_dir = NULL;

#undef test_dir_init
void test_dir_init(const char *top_test_dir, const char *name)
{
	string_t *dir;
	int ret;

	i_assert(test_dir == NULL);

	test_init();
	test_init_signals();

	ret = mkdir(top_test_dir, 0700);
	if (ret < 0 && errno != EEXIST)
		i_fatal("mkdir(%s) failed: %m", TEST_DIR);

	dir = t_str_new(256);
	str_append(dir, top_test_dir);
	str_append_c(dir, '/');
	str_append(dir, name);
	str_append_c(dir, '-');

	if (safe_mkstemp_dir_pid(dir, 0700) < 0)
		i_fatal("safe_mkstemp_dir(%s) failed: %m", str_c(dir));

	test_dir = i_strdup(str_c(dir));
}

void test_dir_cleanup(void)
{
	const char *error;

	if (test_dir == NULL)
		return;
	if (lib_is_initialized()) {
		if (unlink_directory(test_dir,
				     UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0) {
			i_error("unlink_directory(%s) failed: %s.",
				test_dir, error);
		}
	} else {
		/* Not supposed to happen, but automake will drop the main test
		   directory upon the next run, so this will eventually be
		   fixed. */
	}

	i_free(test_dir);
}

void test_dir_deinit(void)
{
	test_dir_cleanup();
}

void test_dir_deinit_forked(void)
{
	i_free(test_dir);
}

const char *test_dir_get(void)
{
	return test_dir;
}

const char *test_dir_get_prefix(void)
{
	return t_strconcat(test_dir, "/", NULL);
}

const char *test_dir_prepend(const char *path)
{
	return t_strconcat(test_dir, "/", path, NULL);
}

