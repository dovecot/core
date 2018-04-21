/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "path-util.h"
#include "unlink-directory.h"
#include "str.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#define TEMP_DIRNAME ".test-path-util"

static const char *tmpdir;
static const char *cwd;
static const char *link1;
static const char *link2;
static const char *link3;
static const char *link4;

static void test_local_path(void)
{
	const char *expected = t_strconcat(cwd, "/README.md", NULL);
	const char *npath = NULL, *error = NULL;
	test_assert(t_normpath_to("README.md", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, expected);
}

static void test_absolute_path_no_change(void)
{
	const char *npath = NULL, *error = NULL;
	test_assert(t_normpath_to("/", "/", &npath, &error) == 0);
	test_assert_strcmp(npath, "/");

	test_assert(t_normpath_to(cwd, cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);
}

static int path_height(const char *p)
{
	int n;
	for (n = 0; *p != '\0'; ++p)
		n += *p == '/';
	return n;
}

static void test_travel_to_root(void)
{
	int l = path_height(cwd);
	const char *npath = cwd;
	for (npath = cwd; l != 0; l--) {
		const char *error;
		test_assert_idx(t_normpath_to("../", npath, &npath, &error) == 0, l);
	}
	test_assert_strcmp(npath, "/");
}

static void test_extra_slashes(void)
{
	const char *npath = NULL, *error = NULL;
	test_assert(t_normpath_to(".", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);

	test_assert(t_normpath_to("./", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);

	test_assert(t_normpath_to(".////", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, cwd);
}

static void test_nonexistent_path(void)
{
	const char *npath = NULL, *error = NULL;
	const char *expected = t_strconcat(cwd, "/nonexistent", NULL);
	test_assert(t_normpath_to("nonexistent", cwd, &npath, &error) == 0);
	test_assert_strcmp(npath, expected);
	test_assert(t_realpath_to("nonexistent", cwd, &npath, &error) == -1);
	test_assert(error != NULL);
}

static void test_relative_dotdot(void)
{
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

static void test_link1(void)
{
	const char *old_dir, *npath = NULL, *error = NULL;
	test_assert(t_realpath_to(link1, "/", &npath, &error) == 0);
	test_assert_strcmp(npath, tmpdir);

	/* .../link1/link1/child */
	test_assert(t_realpath_to(t_strconcat(link1, "/link1/child", NULL),
				  "/", &npath, &error) == 0);
	test_assert_strcmp(npath, t_strconcat(tmpdir, "/child", NULL));

	/* relative link1/link1/child */
	if (t_get_working_dir(&old_dir, &error) < 0)
		i_fatal("t_get_working_dir() failed: %s", error);
	if (chdir(tmpdir) < 0)
		i_fatal("chdir(%s) failed: %m", tmpdir);
	test_assert(t_realpath(t_strconcat("link1", "/link1/child", NULL),
			       &npath, &error) == 0);
	if (chdir(old_dir) < 0)
		i_fatal("chdir(%s) failed: %m", old_dir);
}

static void test_link4(void)
{
	const char *npath = NULL, *error = NULL;

	test_assert(t_realpath_to(t_strconcat(link1, "/link4/child", NULL),
				  "/", &npath, &error) == 0);
	test_assert_strcmp(npath, t_strconcat(tmpdir, "/child", NULL));
}

static void test_link_loop(void)
{
	const char *npath = NULL, *error = NULL;
	errno = 0;
	test_assert(t_realpath_to(link2, "/", &npath, &error) == -1);
	test_assert(errno == ELOOP);
	test_assert(error != NULL);
}

static void test_abspath_vs_normpath(void)
{
	const char *abs = t_abspath_to("../../bin", "/usr/lib/");
	test_assert_strcmp(abs, "/usr/lib//../../bin");

	const char *norm = NULL, *error = NULL;
	test_assert(t_normpath_to("../../bin", "/usr///lib/", &norm, &error) == 0);
	test_assert_strcmp(norm, "/bin");
}

static void create_links(const char *tmpdir)
{
	link1 = t_strconcat(tmpdir, "/link1", NULL);
	if (symlink(tmpdir, link1) < 0)
		i_fatal("symlink(%s, %s) failed: %m", tmpdir, link1);

	const char *link1_child = t_strconcat(link1, "/child", NULL);
	int fd = creat(link1_child, 0600);
	if (fd == -1)
		i_fatal("creat(%s) failed: %m", link1_child);
	i_close_fd(&fd);

	/* link2 and link3 point to each other to create a loop */
	link2 = t_strconcat(tmpdir, "/link2", NULL);
	link3 = t_strconcat(tmpdir, "/link3", NULL);
	if (symlink(link3, link2) < 0)
		i_fatal("symlink(%s, %s) failed: %m", link3, link2);
	if (symlink(link2, link3) < 0)
		i_fatal("symlink(%s, %s) failed: %m", link2, link3);

	/* link4 points to link1 */
	link4 = t_strconcat(tmpdir, "/link4", NULL);
	if (symlink("link1", link4) < 0)
		i_fatal("symlink(link1, %s) failed: %m", link4);
}

static void test_link_alloc(void)
{
#define COMPONENT_COMPONENT "/component-component"
	const char *o_tmpdir;

	/* idea here is to make sure component-component
	   would optimally hit to the nearest_power value.

	   it has to be big enough to cause requirement for
	   allocation in t_realpath. */
	string_t *basedir = t_str_new(256);
	str_append(basedir, cwd);
	str_append(basedir, "/"TEMP_DIRNAME);
	size_t len = nearest_power(I_MAX(127, str_len(basedir) + strlen(COMPONENT_COMPONENT) + 1)) -
			strlen(COMPONENT_COMPONENT);

	while(str_len(basedir) < len) {
		str_append(basedir, COMPONENT_COMPONENT);
		(void)mkdir(str_c(basedir), 0700);
	}
	o_tmpdir = tmpdir;
	tmpdir = str_c(basedir);

	create_links(tmpdir);

	test_link1();
	test_link_loop();

	tmpdir = o_tmpdir;
}

static void test_link_alloc2(void)
{
	const char *o_tmpdir;

	/* try enough different sized base directory lengths so the code
	   hits the different reallocations and tests for off-by-one errors */
	string_t *basedir = t_str_new(256);
	str_append(basedir, cwd);
	str_append(basedir, "/"TEMP_DIRNAME);
	str_append_c(basedir, '/');
	size_t base_len = str_len(basedir);

	o_tmpdir = tmpdir;
	/* path_normalize() initially allocates 128 bytes, so we'll test paths
	   up to that length+1. */
	unsigned char buf[128+1];
	memset(buf, 'x', sizeof(buf));
	for (size_t i = 1; i <= sizeof(buf); i++) {
		str_truncate(basedir, base_len);
		str_append_data(basedir, buf, i);
		tmpdir = str_c(basedir);
		(void)mkdir(str_c(basedir), 0700);

		create_links(tmpdir);
		test_link1();
		test_link_loop();
	}
	tmpdir = o_tmpdir;
}

static void test_cleanup(void)
{
	const char *error;

	if (unlink_directory(tmpdir, UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0)
		i_error("unlink_directory() failed: %s", error);
}

static void test_init(void)
{
	const char *error;
	test_assert(t_get_working_dir(&cwd, &error) == 0);
	tmpdir = t_strconcat(cwd, "/"TEMP_DIRNAME, NULL);

	test_cleanup();
	if (mkdir(tmpdir, 0700) < 0) {
		i_fatal("mkdir: %m");
	}

	create_links(tmpdir);
}

void test_path_util(void)
{
	test_begin("test_path_util");
	alarm(20);
	test_init();
	test_local_path();
	test_absolute_path_no_change();
	test_travel_to_root();
	test_extra_slashes();
	test_nonexistent_path();
	test_relative_dotdot();
	test_link1();
	test_link4();
	test_link_loop();
	test_abspath_vs_normpath();
	test_link_alloc();
	test_link_alloc2();
	test_cleanup();
	alarm(0);
	test_end();
}
