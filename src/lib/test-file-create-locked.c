/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "file-create-locked.h"

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
		usleep(10000);
	}
	i_error("%s isn't being created", path);
	return FALSE;
}

static void test_file_create_locked_basic(void)
{
	struct file_create_settings set = {
		.lock_timeout_secs = 0,
		.lock_method = FILE_LOCK_METHOD_FCNTL,
	};
	const char *path = ".test-file-create-locked";
	struct file_lock *lock;
	const char *error;
	bool created;
	pid_t pid;
	int fd;

	test_begin("file_create_locked()");

	i_unlink_if_exists(path);
	i_unlink_if_exists(".test-temp-file-create-locked-child");
	pid = fork();
	switch (pid) {
	case (pid_t)-1:
		i_error("fork() failed: %m");
		break;
	case 0:
		/* child */
		fd = file_create_locked(path, &set, &lock, &created, &error);
		test_assert(fd > 0);
		test_assert(created);
		if (test_has_failed())
			exit(1);
		create_file(".test-temp-file-create-locked-child");
		sleep(60);
		i_close_fd(&fd);
		exit(0);
	default:
		/* parent */
		test_assert(wait_for_file(pid, ".test-temp-file-create-locked-child"));
		if (test_has_failed())
			break;
		test_assert(file_create_locked(path, &set, &lock, &created, &error) == -1);
		test_assert(errno == EAGAIN);
		if (kill(pid, SIGKILL) < 0)
			i_error("kill(SIGKILL) failed: %m");
		break;
	}
	i_unlink_if_exists(".test-temp-file-create-locked-child");
	test_end();
}

void test_file_create_locked(void)
{
	test_file_create_locked_basic();
}
