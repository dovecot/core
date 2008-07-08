/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "file-dotlock.h"
#include "src/lib-storage/index/maildir/maildir-uidlist.h"

#include <stdio.h>
#include <stdlib.h>
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

static void sig_die(int signo ATTR_UNUSED, void *context ATTR_UNUSED)
{
	io_loop_stop(ioloop);
}

static int maildir_lock(const char *path, unsigned int timeout,
			struct dotlock **dotlock_r)
{
	dotlock_settings.timeout = timeout;
	dotlock_settings.use_excl_lock = getenv("DOTLOCK_USE_EXCL") != NULL;
	dotlock_settings.nfs_flush = getenv("MAIL_NFS_STORAGE") != NULL;

	return file_dotlock_create(&dotlock_settings, path, 0, dotlock_r);
}

int main(int argc, const char *argv[])
{
	struct dotlock *dotlock;
	unsigned int timeout;

	lib_init();
	ioloop = io_loop_create();

	if (argc != 3) {
		printf("Usage: maildirlock <path> <timeout>\n"
		       " - SIGTERM will release the lock.\n");
		return 1;
	}

	timeout = strtoul(argv[2], NULL, 10);
	if (maildir_lock(argv[1], timeout, &dotlock) <= 0)
		return 1;

	lib_signals_init();
	lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
	io_loop_run(ioloop);

	file_dotlock_delete(&dotlock);
	lib_signals_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();
	return 0;
}
