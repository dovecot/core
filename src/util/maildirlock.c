/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "write-full.h"
#include "file-dotlock.h"
#include "index/maildir/maildir-uidlist.h"

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

static struct dotlock_settings dotlock_settings = {
	.stale_timeout = MAILDIR_UIDLIST_LOCK_STALE_TIMEOUT,
	.use_io_notify = TRUE
};

static struct ioloop *ioloop;

static void sig_die(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	io_loop_stop(ioloop);
}

static void release_timeout_cb(void *context ATTR_UNUSED)
{
	io_loop_stop(ioloop);
}

static int maildir_lock(const char *path, unsigned int timeout,
			struct dotlock **dotlock_r)
{
	dotlock_settings.timeout = timeout;
	dotlock_settings.use_excl_lock = getenv("DOTLOCK_USE_EXCL") != NULL;
	dotlock_settings.nfs_flush = getenv("MAIL_NFS_STORAGE") != NULL;

	path = t_strconcat(path, "/" MAILDIR_UIDLIST_NAME, NULL);
	return file_dotlock_create(&dotlock_settings, path, 0, dotlock_r);
}

int main(int argc, const char *argv[])
{
	struct dotlock *dotlock;
	struct timeout *timeout;
	unsigned acquire_timeout_s, release_timeout_s, release_timeout_ms;
	pid_t pid;
	int fd[2], ret;
	char c;

	if (argc < 3 || argc > 4) {
		fprintf(stderr, "Usage: maildirlock <path> <acquire-timeout> [<release-timeout>]\n"
			" - if unspecified, release-timeout will be the same as acquire-timeout;\n"
			"   SIGTERM will release the lock.\n");
		return 1;
	}
	if (pipe(fd) != 0) {
		fprintf(stderr, "pipe() failed: %s", strerror(errno));
		return 1;
	}

	pid = fork();
	if (pid == (pid_t)-1) {
		fprintf(stderr, "fork() failed: %s", strerror(errno));
		return 1;
	}

	/* call lib_init() only after fork so that PID gets set correctly */
	lib_init();
	lib_signals_init();
	ioloop = io_loop_create();
	lib_signals_set_handler(SIGINT, LIBSIG_FLAG_DELAYED, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, LIBSIG_FLAG_DELAYED, sig_die, NULL);

	if (pid != 0) {
		i_close_fd(&fd[1]);
		ret = read(fd[0], &c, 1);
		if (ret < 0) {
			i_error("read(pipe) failed: %m");
			return 1;
		}
		if (ret != 1) {
			/* locking timed out */
			return 1;
		}

		printf("%s", dec2str(pid));
		return 0;
	}

	/* child process - stdout has to be closed so that caller knows when
	   to stop reading it. */
	if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0)
		i_fatal("dup2() failed: %m");

	if (str_to_uint(argv[2], &acquire_timeout_s) < 0)
		i_fatal("Invalid acquire_timeout value: %s", argv[2]);
	if (argc == 4) {
		if (str_to_uint(argv[3], &release_timeout_s) < 0)
			i_fatal("Invalid release_timeout value: %s", argv[3]);
	} else
		release_timeout_s = acquire_timeout_s;
	release_timeout_ms = release_timeout_s * 1000;
	if (release_timeout_ms / 1000 != release_timeout_s)
		i_fatal("release_timeout value too large");

	if (maildir_lock(argv[1], acquire_timeout_s, &dotlock) <= 0)
		return 1;

	/* locked - send a byte */
	if (write_full(fd[1], "", 1) < 0)
		i_fatal("write(pipe) failed: %m");

	timeout = timeout_add(release_timeout_ms, release_timeout_cb, NULL);
	io_loop_run(ioloop);

	file_dotlock_delete(&dotlock);
	timeout_remove(&timeout);
	lib_signals_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();
	return 0;
}
