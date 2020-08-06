/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "hostpid.h"
#include "array.h"
#include "ioloop.h"
#include "test-common.h"
#include "test-subprocess.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct test_subprocess {
	pid_t pid;
};

volatile sig_atomic_t test_subprocess_is_child = 0;
static bool test_subprocess_lib_init = FALSE;
static struct event *test_subprocess_event = NULL;
static ARRAY(struct test_subprocess *) test_subprocesses = ARRAY_INIT;
static void (*test_subprocess_cleanup_callback)(void) = NULL;

static void
test_subprocess_signal(const siginfo_t *si ATTR_UNUSED,
		       void *context ATTR_UNUSED)
{
	io_loop_stop(current_ioloop);
}

static void test_subprocess_free_all(void)
{
	struct test_subprocess **subpp;

	array_foreach_modifiable(&test_subprocesses, subpp)
		i_free(*subpp);
	array_free(&test_subprocesses);
}

static void ATTR_NORETURN
test_subprocess_child(int (*func)(void *context), void *context,
		      bool continue_test)
{
	int ret;

	if (!continue_test)
		test_forked_end();

	hostpid_init();

	lib_signals_deinit();
	lib_signals_init();

	lib_signals_set_handler(SIGTERM,
		LIBSIG_FLAG_DELAYED | LIBSIG_FLAG_IOLOOP_AUTOMOVE,
		test_subprocess_signal, NULL);
	lib_signals_set_handler(SIGQUIT,
		LIBSIG_FLAG_DELAYED | LIBSIG_FLAG_IOLOOP_AUTOMOVE,
		test_subprocess_signal, NULL);
	lib_signals_set_handler(SIGINT,
		LIBSIG_FLAG_DELAYED | LIBSIG_FLAG_IOLOOP_AUTOMOVE,
		test_subprocess_signal, NULL);

	ret = func(context);

	/* Prevent race condition */
	lib_signals_clear_handlers_and_ignore(SIGTERM);

	event_unref(&test_subprocess_event);
	lib_signals_deinit();

	if (!continue_test) {
		lib_deinit();
		exit(ret);
	}
	test_exit((test_has_failed() ? 1 : 0));
}

#undef test_subprocess_fork
void test_subprocess_fork(int (*func)(void *context), void *context,
			  bool continue_test)
{
	struct test_subprocess *subprocess;

	subprocess = i_new(struct test_subprocess, 1);
	array_push_back(&test_subprocesses, &subprocess);

	lib_signals_ioloop_detach();

	if ((subprocess->pid = fork()) == (pid_t)-1)
		i_fatal("test: sub-process: fork() failed: %m");
	if (subprocess->pid == 0) {
		test_subprocess_is_child = 1;
		test_subprocess_free_all();

		test_subprocess_child(func, context, continue_test);
		i_unreached();
	}

	lib_signals_ioloop_attach();
}

static void test_subprocess_verify_exit_status(int status)
{
	test_out_quiet("sub-process ended properly",
		       WIFEXITED(status) && WEXITSTATUS(status) == 0);
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0) {
			e_warning(test_subprocess_event,
				  "Sub-process exited with status %d",
				  WEXITSTATUS(status));
		}
	} else if (WIFSIGNALED(status)) {
		e_warning(test_subprocess_event,
			  "Sub-process forcibly terminated with signal %d",
		          WTERMSIG(status));
	} else if (WIFSTOPPED(status)) {
		e_warning(test_subprocess_event,
			  "Sub-process stopped with signal %d",
			  WSTOPSIG(status));
	} else {
		e_warning(test_subprocess_event,
			  "Sub-process terminated abnormally with status %d",
			  status);
	}
}

static void test_subprocess_kill_forced(struct test_subprocess *subp)
{
	(void)kill(subp->pid, SIGKILL);
	(void)waitpid(subp->pid, NULL, 0);
}

void test_subprocess_kill_all(unsigned int timeout_secs)
{
	struct test_subprocess **subps;
	unsigned int subps_count, subps_left, i;

	subps = array_get_modifiable(&test_subprocesses, &subps_count);

	/* Request children to terminate gently */
	for (i = 0; i < subps_count; i++) {
		if (subps[i] == NULL || subps[i]->pid == (pid_t)-1)
			continue;

		e_debug(test_subprocess_event,
			"Terminating sub-process [%u]", i);
		if (kill(subps[i]->pid, SIGTERM) < 0) {
			e_error(test_subprocess_event,
				"Failed to kill sub-process [%u] with SIGTERM: "
				"%m", i);
		}
	}

	/* Wait for children */
	subps_left = subps_count;
	while (subps_left > 0) {
		int status;
		pid_t wret = (pid_t)-1;

		alarm(timeout_secs);
		wret = waitpid(-1, &status, 0);
		alarm(0);

		test_assert(wret > 0);
		if (wret < 0 && errno == EINTR)
			e_warning(test_subprocess_event,
				  "Wait for sub-processes timed out");
		if (wret > 0)
			test_subprocess_verify_exit_status(status);

		if (wret == 0)
			break;
		if (wret < 0) {
			if (errno == ECHILD)
				continue;
			e_warning(test_subprocess_event,
				  "Wait for sub-processes failed: %m");
			break;
		}
		for (i = 0; i < subps_count; i++) {
			if (subps[i] == NULL || subps[i]->pid != wret)
				continue;
			e_debug(test_subprocess_event,
				"Terminated sub-process [%u]", i);
			i_free(subps[i]);
			subps_left--;
		}
	}

	/* Kill disobedient ones with fire */
	for (i = 0; i < subps_count; i++) {
		if (subps[i] == NULL || subps[i]->pid == (pid_t)-1)
			continue;
		e_warning(test_subprocess_event,
			  "Forcibly killed sub-process [%u]", i);
		test_subprocess_kill_forced(subps[i]);
		i_assert(subps_left > 0);
		i_free(subps[i]);
		subps_left--;
	}
	i_assert(subps_left == 0);

	array_clear(&test_subprocesses);
}

static void test_subprocess_kill_all_forced(void)
{
	struct test_subprocess **subps;
	unsigned int subps_count, i;

	if (!array_is_created(&test_subprocesses))
		return;

	/* This is also called from signal handler context, so no debug logging
	   here.
	 */

	subps = array_get_modifiable(&test_subprocesses, &subps_count);

	if (subps_count == 0)
		return;

	for (i = 0; i < subps_count; i++) {
		if (subps[i] == NULL || subps[i]->pid == (pid_t)-1)
			continue;
		test_subprocess_kill_forced(subps[i]);
		subps[i]->pid = (pid_t)-1;
	}
}

/*
 * Main
 */

volatile sig_atomic_t terminating = 0;

static void test_subprocess_cleanup(void)
{
	if (test_subprocess_is_child != 0) {
		/* Child processes must not execute the cleanups */
		return;
	}

	/* We get here when the test ended normally, badly failed, crashed,
	   terminated, or executed exit() unexpectedly. The cleanups performed
	   here are important and must be executed at all times. */

	/* While any unfreed memory will be handled by the system, lingering
	   child processes will not be handled so well. So, we need to make sure
	   here that we don't leave any pesky child processes alive. */
	test_subprocess_kill_all_forced();

	/* Perform any additional important cleanup specific to the test. */
	if (test_subprocess_cleanup_callback != NULL)
		test_subprocess_cleanup_callback();
}

static void
test_subprocess_alarm(const siginfo_t *si ATTR_UNUSED,
		      void *context ATTR_UNUSED)
{
	/* We use alarm() to implement a simple timeout on waitpid(), which will
	   exit with EINTR when SIGALRM is received. This handler overrides the
	   default SIGALRM handler, so that the process is not killed and no
	   messages are printed to terminal.
	 */
}

static void
test_subprocess_terminate(const siginfo_t *si, void *context ATTR_UNUSED)
{
	int signo = si->si_signo;

	if (terminating != 0)
		raise(signo);
	terminating = 1;

	/* Perform important cleanups */
	test_subprocess_cleanup();

	(void)signal(signo, SIG_DFL);
	raise(signo);
}

static void test_atexit(void)
{
	/* NOTICE: This is also called by children, so be careful. */

	/* Perform important cleanups */
	test_subprocess_cleanup();
}

void test_subprocess_set_cleanup_callback(void (*callback)(void))
{
	test_subprocess_cleanup_callback = callback;
}

void test_subprocesses_init(bool debug)
{
	if (!lib_is_initialized()) {
		lib_init();
		test_subprocess_lib_init = TRUE;
	}
	lib_signals_init();

	atexit(test_atexit);
	lib_signals_ignore(SIGPIPE, TRUE);
	lib_signals_set_handler(SIGALRM, 0, test_subprocess_alarm, NULL);
	lib_signals_set_handler(SIGTERM, 0, test_subprocess_terminate, NULL);
	lib_signals_set_handler(SIGQUIT, 0, test_subprocess_terminate, NULL);
	lib_signals_set_handler(SIGINT, 0, test_subprocess_terminate, NULL);
	lib_signals_set_handler(SIGSEGV, 0, test_subprocess_terminate, NULL);
	lib_signals_set_handler(SIGABRT, 0, test_subprocess_terminate, NULL);

	i_array_init(&test_subprocesses, 8);

	test_subprocess_event = event_create(NULL);
	event_set_forced_debug(test_subprocess_event, debug);
	event_set_append_log_prefix(test_subprocess_event, "test: ");
}

void test_subprocesses_deinit(void)
{
	test_subprocess_cleanup();
	test_subprocess_free_all();
	array_free(&test_subprocesses);

	event_unref(&test_subprocess_event);
	lib_signals_deinit();

	if (test_subprocess_lib_init)
		lib_deinit();
}
