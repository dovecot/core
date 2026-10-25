/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "module-dir.h"
#include "unlink-directory.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_module_dir_load_failure(void)
{
	const char *dir = test_dir_prepend("module-dir");
	const char *path = t_strdup_printf("%s/libtest-bad" MODULE_SUFFIX, dir);
	const char *const module_names[] = { "test-bad", NULL };
	const struct module_dir_load_settings set = {
		.abi_version = DOVECOT_ABI_VERSION,
	};
	struct module *modules = NULL;
	const char *error, *error_prefix, *rest;
	int fd;

	test_begin("module dir load failure");

	if (mkdir(dir, 0700) < 0 && errno != EEXIST)
		i_fatal("mkdir(%s) failed: %m", dir);
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	if (write(fd, "not a shared object", 19) != 19)
		i_fatal("write(%s) failed: %m", path);
	i_close_fd(&fd);

	/* The error is created while loading the module, so it mustn't be
	   left pointing to freed data stack. */
	error_prefix = t_strdup_printf(
		"Couldn't load required plugin %s: dlopen() failed: ", path);
	test_assert(module_dir_try_load_missing(&modules, dir, module_names,
						&set, &error) < 0);
	test_assert(modules == NULL);
	if (str_begins(error, error_prefix, &rest)) {
		const char *suffix = " (trying to load modules: test-bad)";
		size_t len = strlen(rest);

		test_assert(len > strlen(suffix));
		test_assert_strcmp(rest + len - strlen(suffix), suffix);
		for (size_t i = 0; i < len; i++)
			test_assert_idx(rest[i] >= 0x20 && rest[i] < 0x7f, i);
	} else {
		test_assert_strcmp(error, error_prefix);
	}

	const char *const missing_names[] = { "test-missing", NULL };
	test_assert(module_dir_try_load_missing(&modules, dir, missing_names,
						&set, &error) < 0);
	test_assert_strcmp(error, t_strdup_printf(
		"Plugin 'test-missing' not found from directory %s "
		"(trying to load modules: test-missing)", dir));

	const char *unlink_error;
	if (unlink_directory(dir, UNLINK_DIRECTORY_FLAG_RMDIR,
			     &unlink_error) < 0)
		i_error("unlink_directory(%s) failed: %s", dir, unlink_error);
	test_end();
}

void test_module_dir(void)
{
	test_module_dir_load_failure();
}
