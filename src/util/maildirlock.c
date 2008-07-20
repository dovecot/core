/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "file-dotlock.h"
#include "maildir-uidlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

static struct dotlock_settings dotlock_settings = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,
	MEMBER(timeout) 0,
	MEMBER(stale_timeout) MAILDIR_UIDLIST_LOCK_STALE_TIMEOUT,
	MEMBER(use_excl_lock) FALSE,
	MEMBER(nfs_flush) FALSE,
	MEMBER(use_io_notify) TRUE
};

static struct ioloop *ioloop;
static bool success = FALSE;

static void sig_die(int signo, void *context ATTR_UNUSED)
{
	success = signo == SIGTERM;
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
	unsigned int timeout;
	pid_t pid, parent_pid;

	if (argc != 3) {
		fprintf(stderr, "Usage: maildirlock <path> <timeout>\n"
			" - SIGTERM will release the lock.\n");
		return 1;
	}
	parent_pid = getpid();

	pid = fork();
	if (pid == (pid_t)-1) {
		fprintf(stderr, "fork() failed: %m");
		return 1;
	}

	/* call lib_init() only after fork so that PID gets set correctly */
	lib_init();
	ioloop = io_loop_create();
	lib_signals_init();
	lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
	lib_signals_set_handler(SIGCHLD, TRUE, sig_die, NULL);

	if (pid != 0) {
		/* master - wait for the child process to finish locking */
		io_loop_run(ioloop);
		if (!success)
			return 1;
		printf("%s", dec2str(pid));
		return 0;
	}

	/* child process - stdout has to be closed so that caller knows when
	   to stop reading it. */
	dup2(STDERR_FILENO, STDOUT_FILENO);

	timeout = strtoul(argv[2], NULL, 10);
	if (maildir_lock(argv[1], timeout, &dotlock) <= 0)
		return 1;

	/* locked - send a  */
	if (kill(parent_pid, SIGTERM) < 0)
		i_fatal("kill(parent, SIGTERM) failed: %m");
	io_loop_run(ioloop);

	file_dotlock_delete(&dotlock);
	lib_signals_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();
	return 0;
}
