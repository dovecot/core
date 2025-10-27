/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "unlink-directory.h"
#include "file-create-locked.h"
#include "sleep.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>

static void create_file(const char *path)
{
	int fd;

	fd = creat(path, 0600);
	if (fd == -1)
		i_fatal("creat(%s) failed: %m", path);
	i_close_fd(&fd);
}

static bool wait_for_file(pid_t pid, const char *path)
{
	struct stat st;

	for (unsigned int i = 0; i < 1000; i++) {
		if (stat(path, &st) == 0)
			return TRUE;
		if (errno != ENOENT)
			i_fatal("stat(%s) failed: %m", path);
		if (kill(pid, 0) < 0) {
			if (errno == ESRCH)
				return FALSE;
			i_fatal("kill(SIGSRCH) failed: %m");
		}
		i_sleep_msecs(10);
	}
	i_error("%s isn't being created", path);
	return FALSE;
}

static int test_file_create_locked_basic_child(void *context ATTR_UNUSED)
{
	struct file_create_settings set = {
		.lock_timeout_secs = 0,
		.lock_settings = {
			.lock_method = FILE_LOCK_METHOD_FCNTL,
		},
	};
	const char *path = ".test-file-create-locked";
	struct file_lock *lock = NULL;
	const char *error;
	bool created;
	int fd;

	/* child */
	fd = file_create_locked(path, &set, &lock, &created, &error);
	test_assert(fd > 0);
	test_assert(created);
	if (test_has_failed())
	       return 1;
	create_file(".test-temp-file-create-locked-child");
	i_sleep_intr_secs(60);
	if (lock != NULL)
		file_unlock(&lock);
	i_close_fd(&fd);
	return 0;
}

static void test_file_create_locked_basic(void)
{
	struct file_create_settings set = {
		.lock_timeout_secs = 0,
		.lock_settings = {
			.lock_method = FILE_LOCK_METHOD_FCNTL,
		},
	};
	const char *path = ".test-file-create-locked";
	struct file_lock *lock = NULL;
	const char *error;
	pid_t pid;
	bool created;

	test_begin("file_create_locked()");

	i_unlink_if_exists(path);
	i_unlink_if_exists(".test-temp-file-create-locked-child");
	pid = test_subprocess_fork(test_file_create_locked_basic_child, NULL,
				   TRUE);

	/* parent */
	test_assert(wait_for_file(pid, ".test-temp-file-create-locked-child"));
	if (!test_has_failed()) {
		test_assert(file_create_locked(path, &set,
					       &lock, &created, &error) == -1);
		test_assert(errno == EAGAIN);
		if (lock != NULL)
			file_unlock(&lock);
	}
	test_subprocess_kill_all(20);
	i_unlink_if_exists(".test-temp-file-create-locked-child");
	i_unlink_if_exists(path);
	test_end();
}

static void test_file_create_locked_mkdir(void)
{
	struct file_create_settings set = {
		.lock_timeout_secs = 0,
		.lock_settings = {
			.lock_method = FILE_LOCK_METHOD_FCNTL,
		},
	};
	const char *path;
	struct file_lock *lock;
	const char *error, *dir;
	bool created;
	int fd;

	test_begin("file_create_locked() with mkdir");

	dir = ".test-temp-file-create-locked-dir";
	if (unlink_directory(dir, UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0)
		i_fatal("unlink_directory(%s) failed: %s", dir, error);
	path = t_strconcat(dir, "/lockfile", NULL);

	/* try without mkdir enabled */
	test_assert(file_create_locked(path, &set, &lock, &created, &error) == -1);
	test_assert(errno == ENOENT);

	/* try with mkdir enabled */
	set.mkdir_mode = 0700;
	fd = file_create_locked(path, &set, &lock, &created, &error);
	test_assert(fd > 0);
	test_assert(created);
	i_close_fd(&fd);

	struct stat st;
	if (stat(dir, &st) < 0)
		i_error("stat(%s) failed: %m", dir);
	test_assert((st.st_mode & 0777) == 0700);
	i_unlink(path);
	file_lock_free(&lock);

	if (unlink_directory(dir, UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0)
		i_fatal("unlink_directory(%s) failed: %s", dir, error);

	test_end();
}

void test_file_create_locked(void)
{
	test_file_create_locked_basic();
	test_file_create_locked_mkdir();
}
