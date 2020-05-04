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

void test_subprocesses_init(bool debug);
void test_subprocesses_deinit(void);

#endif
