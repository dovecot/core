#ifndef TEST_SUBPROCESS_H
#define TEST_SUBPROCESS_H

struct test_subprocess;

/* Fork a sub-process for this test. The func is the main function for the
   forked sub-process. The provided context is passed to the provided function.
   When continue_test=FALSE, the test is ended immediately in the sub-process,
   otherwise, the test continues and its result is used to set the exit code
   when the process ends gracefully. */
void test_subprocess_fork(int (*func)(void *), void *context,
			  bool continue_test);
#define test_subprocess_fork(func, context, continue_test) \
	test_subprocess_fork( \
		(int(*)(void*))func, \
		(TRUE ? context : \
		 CALLBACK_TYPECHECK(func, int(*)(typeof(context)))), \
		continue_test)

void test_subprocess_kill_all(unsigned int timeout_secs);

/* Set a cleanup callback that is executed even when the test program crashes or
   exit()s unexpectedly. Note that this may be run in signal context. */
void test_subprocess_set_cleanup_callback(void (*callback)(void));

/* Send a notification signal (SIGHUP) to the given PID */
void test_subprocess_notify_signal_send(int signo, pid_t pid);
/* Send a notificatino signal to the parent process. */
void test_subprocess_notify_signal_send_parent(int signo);
/* Reset any previously sent notification signals. */
void test_subprocess_notify_signal_reset(int signo);
/* Wait until a notification signal is sent, or return immediately if it was
   already sent. test_subprocess_notify_signal_reset() should be called before
   this to make sure it's not returning due to a previously sent signal.
   If the timeout is reached, i_fatal() is called. */
void test_subprocess_notify_signal_wait(int signo, unsigned int timeout_msecs);

void test_subprocesses_init(bool debug);
void test_subprocesses_deinit(void);

#endif
