/* Copyright (c) 2007-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "hash.h"
#include "child-wait.h"

#include <sys/wait.h>

struct child_wait {
	unsigned int pid_count;

	child_wait_callback_t *callback;
	void *context;
};

HASH_TABLE(pid_t, struct child_wait *) child_pids;

#undef child_wait_new_with_pid
struct child_wait *
child_wait_new_with_pid(pid_t pid, child_wait_callback_t *callback,
			void *context)
{
	struct child_wait *wait;

	wait = i_new(struct child_wait, 1);
	wait->callback = callback;
	wait->context = context;

	if (pid != (pid_t)-1)
		child_wait_add_pid(wait, pid);
	return wait;
}

void child_wait_free(struct child_wait **_wait)
{
	struct child_wait *wait = *_wait;
	struct hash_iterate_context *iter;
	void *key, *value;
	pid_t pid;

	*_wait = NULL;

	if (wait->pid_count > 0) {
		/* this should be rare, so iterating hash is fast enough */
		iter = hash_table_iterate_init(child_pids);
		while (hash_table_iterate(iter, &key, &value)) {
			if (value == wait) {
				pid = POINTER_CAST_TO(key, pid_t);
				hash_table_remove(child_pids, pid);
				if (--wait->pid_count == 0)
					break;
			}
		}
		hash_table_iterate_deinit(&iter);
	}

	i_free(wait);
}

void child_wait_add_pid(struct child_wait *wait, pid_t pid)
{
	wait->pid_count++;
	hash_table_insert(child_pids, pid, wait);
}

void child_wait_remove_pid(struct child_wait *wait, pid_t pid)
{
	wait->pid_count--;
	hash_table_remove(child_pids, pid);
}

static void
sigchld_handler(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	struct child_wait_status status;

	while ((status.pid = waitpid(-1, &status.status, WNOHANG)) > 0) {
		status.wait = hash_table_lookup(child_pids, status.pid);
		if (status.wait != NULL) {
			child_wait_remove_pid(status.wait, status.pid);
			status.wait->callback(&status, status.wait->context);
		}
	}

	if (status.pid == -1 && errno != EINTR && errno != ECHILD)
		i_error("waitpid() failed: %m");
}

void child_wait_init(void)
{
	hash_table_create_direct(&child_pids, default_pool, 0);

	lib_signals_set_handler(SIGCHLD, LIBSIG_FLAGS_SAFE,
				sigchld_handler, NULL);
}

void child_wait_deinit(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	lib_signals_unset_handler(SIGCHLD, sigchld_handler, NULL);

	iter = hash_table_iterate_init(child_pids);
	while (hash_table_iterate(iter, &key, &value))
		i_free(value);
	hash_table_iterate_deinit(&iter);

	hash_table_destroy(&child_pids);
}
