/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>

#include "test-lib.h"
#include "path-util.h"

static char tmpdir[64];
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
	for (npath = cwd; l--;) {
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
	const char *rel_path = t_strconcat("../", basename(tmpdir), NULL);
	const char *npath = NULL, *error = NULL;
	test_assert(t_normpath_to(rel_path, tmpdir, &npath, &error) == 0);
	test_assert_strcmp(npath, tmpdir);

	test_assert(t_normpath_to("..", tmpdir, &npath, &error) == 0);
	test_assert_strcmp(npath, "/tmp");

	test_assert(t_normpath_to("../", tmpdir, &npath, &error) == 0);
	test_assert_strcmp(npath, "/tmp");

	test_assert(t_normpath_to("../.", tmpdir, &npath, &error) == 0);
	test_assert_strcmp(npath, "/tmp");
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

static void test_init(void) {
	const char *error;
	test_assert(t_get_working_dir(&cwd, &error) == 0);
	strcpy(tmpdir, "/tmp/tmpdir.XXXXXX");
	if (mkdtemp(tmpdir) == NULL) {
		i_fatal("mkdtemp: %m");
	}

	link1 = t_strconcat(tmpdir, "/link1", NULL);
	if (symlink(tmpdir, link1) < 0) {
		i_fatal("symlink: %m");
	}

	/* link2 and link3 point to each other to create a loop */
	link2 = t_strconcat(tmpdir, "/link2", NULL);
	link3 = t_strconcat(tmpdir, "/link3", NULL);
	if (symlink(link3, link2) < 0) {
		i_fatal("symlink: %m");
	}
	if (symlink(link2, link3) < 0) {
		i_fatal("symlink: %m");
	}
}

static void test_deinit(void) {
	if (unlink(link1) < 0) {
		i_fatal("unlink: %m");
	} if (unlink(link2) < 0) {
		i_fatal("unlink: %m");
	} if (unlink(link3) < 0) {
		i_fatal("unlink: %m");
	} if (rmdir(tmpdir) < 0) {
		i_fatal("rmdir: %m");
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
	test_deinit();
	test_end();
}
