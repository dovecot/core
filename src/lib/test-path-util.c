/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "path-util.h"
#include "unlink-directory.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

#define TEMP_DIRNAME ".test-path-util"

static const char *tmpdir;
static const char *cwd;
static const char *link1;
static const char *link2;
static const char *link3;

static void test_local_path() {
	const char *expected = t_strconcat(cwd, "/README.md", NULL);
	const char *npath = NULL, *error = NULL;
	test_assert(t_normpath_to("README.md", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, expected);
}

static void test_absolute_path_no_change(void) {
	const char *npath = NULL, *error = NULL;
	test_assert(t_normpath_to("/", "/", &npath, &error) == 0);
	test_assert_strcmp(npath, "/");

	test_assert(t_normpath_to(cwd, cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);
}

static int path_height(const char* p) {
	int n;
	for (n = 0; *p != '\0'; ++p)
		n += *p == '/';
	return n;
}

static void test_travel_to_root(void) {
	int l = path_height(cwd);
	const char *npath = cwd;
	for (npath = cwd; l != 0; l--) {
		const char *error;
		test_assert_idx(t_normpath_to("../", npath, &npath, &error) == 0, l);
	}
	test_assert_strcmp(npath, "/");
}

static void test_extra_slashes(void) {
	const char *npath = NULL, *error = NULL;
	test_assert(t_normpath_to(".", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);

	test_assert(t_normpath_to("./", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);

	test_assert(t_normpath_to(".////", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);
}

static void test_nonexistent_path(void) {
	const char *npath = NULL, *error = NULL;
	const char *expected = t_strconcat(cwd, "/nonexistent", NULL);
	test_assert(t_normpath_to("nonexistent", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, expected);
	test_assert(t_realpath_to("nonexistent", cwd, &npath, &error) == -1);
	test_assert(error != NULL);
}

static void test_relative_dotdot() {
	const char *rel_path = "../"TEMP_DIRNAME;
	const char *npath = NULL, *error = NULL;
	test_assert(t_normpath_to(rel_path, tmpdir, &npath, &error) == 0);
	test_assert_strcmp(npath, tmpdir);

	test_assert(t_normpath_to("..", tmpdir, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);

	test_assert(t_normpath_to("../", tmpdir, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);

	test_assert(t_normpath_to("../.", tmpdir, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);
}

static void test_link1() {
	const char *npath = NULL, *error = NULL;
	test_assert(t_realpath_to(link1, "/", &npath, &error) == 0);
	test_assert_strcmp(npath, tmpdir);
}

static void test_link_loop() {
	const char *npath = NULL, *error = NULL;
	errno = 0;
	test_assert(t_realpath_to(link2, "/", &npath, &error) == -1);
	test_assert(errno == ELOOP);
	test_assert(error != NULL);
}

static void test_abspath_vs_normpath() {
	const char *abs = t_abspath_to("../../bin", "/usr/lib/");
	test_assert_strcmp(abs, "/usr/lib//../../bin");

	const char *norm = NULL, *error = NULL;
	test_assert(t_normpath_to("../../bin", "/usr///lib/", &norm, &error) == 0);
	test_assert_strcmp(norm, "/bin");
}

static void test_cleanup(void)
{
	const char *error;

	if (unlink_directory(tmpdir, UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0)
		i_error("unlink_directory() failed: %s", error);
}

static void test_init(void) {
	const char *error;
	test_assert(t_get_working_dir(&cwd, &error) == 0);
	tmpdir = t_strconcat(cwd, "/"TEMP_DIRNAME, NULL);

	test_cleanup();
	if (mkdir(tmpdir, 0700) < 0) {
		i_fatal("mkdir: %m");
	}

	link1 = t_strconcat(tmpdir, "/link1", NULL);
	if (symlink(tmpdir, link1) < 0) {
		i_fatal("symlink(%s, %s) failed: %m", tmpdir, link1);
	}

	/* link2 and link3 point to each other to create a loop */
	link2 = t_strconcat(tmpdir, "/link2", NULL);
	link3 = t_strconcat(tmpdir, "/link3", NULL);
	if (symlink(link3, link2) < 0) {
		i_fatal("symlink(%s, %s) failed: %m", link3, link2);
	}
	if (symlink(link2, link3) < 0) {
		i_fatal("symlink(%s, %s) failed: %m", link2, link3);
	}
}

void test_path_util(void) {
	test_begin("test_path_util");
	test_init();
	test_local_path();
	test_absolute_path_no_change();
	test_travel_to_root();
	test_extra_slashes();
	test_nonexistent_path();
	test_relative_dotdot();
	test_link1();
	test_link_loop();
	test_abspath_vs_normpath();
	test_cleanup();
	test_end();
}
