/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "lib-signals.h"
#include "file-lock.h"
#include "sleep.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOCK_PATH_NAME "test-file-lock"
#define MARKER_PATH_NAME "test-file-lock-child-locked"
#define STOP_PATH_NAME "test-file-lock-parent-done"
#define ACK_PATH_NAME "test-file-lock-child-stopped"

struct test_file_lock_child {
	enum file_lock_method lock_method;
	/* Unlock after this many msecs. 0 means keeping the lock until the
	   child is killed. */
	unsigned int unlock_msecs;
};

static bool test_file_lock_simulate_term_signal = FALSE;

static void
test_file_lock_signal_handler(const siginfo_t *si ATTR_UNUSED,
			      void *context ATTR_UNUSED)
{
	/* The test framework's SIGTERM handler exits the process, so a real
	   termination signal can't be used here. Increase the counter
	   manually instead - that's all the locking code looks at. */
	if (test_file_lock_simulate_term_signal)
		signal_term_counter++;
}

static int test_file_lock_open(const char *path)
{
	int fd = open(path, O_RDWR | O_CREAT, 0600);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	return fd;
}

static void test_file_lock_create_file(const char *path)
{
	int fd = test_file_lock_open(path);
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

static int test_file_lock_child(struct test_file_lock_child *child)
{
	struct file_lock_settings set = {
		.lock_method = child->lock_method,
	};
	const char *path = test_dir_prepend(LOCK_PATH_NAME);
	const char *marker_path = test_dir_prepend(MARKER_PATH_NAME);
	const char *stop_path = test_dir_prepend(STOP_PATH_NAME);
	const char *ack_path = test_dir_prepend(ACK_PATH_NAME);
	struct file_lock *lock = NULL;
	const char *error;
	struct stat st;
	unsigned int msecs = 0;
	int fd;

	fd = test_file_lock_open(path);
	if (file_wait_lock(fd, path, F_WRLCK, &set, 0, &lock, &error) != 1)
		i_fatal("child: file_wait_lock() failed: %s", error);

	test_file_lock_create_file(marker_path);

	/* Keep interrupting the parent's lock wait until it's finished. The
	   signals that are sent before the parent is waiting for the lock are
	   harmless. */
	while (stat(stop_path, &st) < 0) {
		i_sleep_msecs(50);
		msecs += 50;
		if (child->unlock_msecs != 0 && msecs >= child->unlock_msecs)
			break;
		if (kill(getppid(), SIGUSR2) < 0)
			i_fatal("child: kill() failed: %m");
	}
	/* let the parent know that no more signals are coming */
	test_file_lock_create_file(ack_path);
	if (child->unlock_msecs != 0)
		file_unlock(&lock);
	/* Wait until the parent kills us, so the parent's lock wait can't
	   succeed or fail just because the child died. */
	while (stat(stop_path, &st) < 0)
		i_sleep_msecs(50);
	file_lock_free(&lock);
	i_close_fd(&fd);
	return 0;
}

static void
test_file_lock_interrupted(enum file_lock_method lock_method, bool term_signal)
{
	struct file_lock_settings set = {
		.lock_method = lock_method,
	};
	struct test_file_lock_child child = {
		.lock_method = lock_method,
		.unlock_msecs = term_signal ? 0 : 500,
	};
	const char *path = test_dir_prepend(LOCK_PATH_NAME);
	const char *marker_path = test_dir_prepend(MARKER_PATH_NAME);
	const char *stop_path = test_dir_prepend(STOP_PATH_NAME);
	const char *ack_path = test_dir_prepend(ACK_PATH_NAME);
	struct file_lock *lock = NULL;
	const char *error;
	pid_t pid;
	int fd, ret;

	test_begin(t_strdup_printf("file_wait_lock() interrupted by %s signal (%s)",
				   term_signal ? "a termination" : "an ignored",
				   file_lock_method_to_str(lock_method)));

	i_unlink_if_exists(path);
	i_unlink_if_exists(marker_path);
	i_unlink_if_exists(stop_path);
	i_unlink_if_exists(ack_path);

	test_file_lock_simulate_term_signal = term_signal;
	lib_signals_set_handler(SIGUSR2, 0, test_file_lock_signal_handler, NULL);

	fd = test_file_lock_open(path);
	pid = test_subprocess_fork(test_file_lock_child, &child, TRUE);
	if (wait_for_file(pid, marker_path)) {
		ret = file_wait_lock(fd, path, F_WRLCK, &set, 30,
				     &lock, &error);
		if (term_signal) {
			/* the lock wait was aborted */
			test_assert(ret == -1);
			test_assert(errno == EINTR);
			test_assert(lock == NULL);
		} else {
			/* the signals didn't abort the lock wait */
			test_assert(ret == 1);
			test_assert(lock != NULL);
		}
		if (ret < 0)
			test_assert(strstr(error, "Interrupted") != NULL);
		file_lock_free(&lock);
	}
	/* stop the child from sending any more signals, which would
	   interrupt waitpid() below */
	test_file_lock_create_file(stop_path);
	(void)wait_for_file(pid, ack_path);
	test_subprocess_kill_all(20);
	i_close_fd(&fd);

	lib_signals_unset_handler(SIGUSR2, test_file_lock_signal_handler, NULL);
	test_file_lock_simulate_term_signal = FALSE;

	i_unlink_if_exists(ack_path);
	i_unlink_if_exists(stop_path);
	i_unlink_if_exists(marker_path);
	i_unlink_if_exists(path);
	test_end();
}

void test_file_lock(void)
{
	static const enum file_lock_method lock_methods[] = {
		FILE_LOCK_METHOD_FCNTL,
		FILE_LOCK_METHOD_FLOCK,
	};
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(lock_methods); i++) {
		test_file_lock_interrupted(lock_methods[i], FALSE);
		test_file_lock_interrupted(lock_methods[i], TRUE);
	}
}
