/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "time-util.h"
#include "ioloop.h"
#include "lib-signals.h"

#include <unistd.h>
#include <sys/types.h>

struct test_context_delayed {
	bool timed_out:1;
	bool signal_handled:1;
};

static void
kill_timeout(struct test_context_delayed *tctx ATTR_UNUSED)
{
	if (kill(getpid(), SIGALRM) < 0)
		i_fatal("Failed to send signal: %m");
}

static void
test_timeout(struct test_context_delayed *tctx)
{
	tctx->timed_out = TRUE;
	io_loop_stop(current_ioloop);
}

static void
signal_handler_delayed(const siginfo_t *si ATTR_UNUSED,
	void *context ATTR_UNUSED)
{
	struct test_context_delayed *tctx =
		(struct test_context_delayed *)context;
	tctx->signal_handled = TRUE;
	io_loop_stop(current_ioloop);
}

static void
test_lib_signals_delayed(void)
{
	struct test_context_delayed tctx;
	struct timeout *to_kill, *to_test;
	struct ioloop *ioloop;

	test_begin("lib-signals delayed - init lib-signals first");

	i_zero(&tctx);

	lib_signals_init();
	lib_signals_set_handler(SIGALRM,
		LIBSIG_FLAGS_SAFE | LIBSIG_FLAG_IOLOOP_AUTOMOVE,
		signal_handler_delayed, &tctx);

	ioloop = io_loop_create();
	to_kill = timeout_add_short(200, kill_timeout, &tctx);
	to_test = timeout_add_short(400, test_timeout, &tctx);
	io_loop_run(ioloop);

	timeout_remove(&to_kill);
	timeout_remove(&to_test);
	io_loop_destroy(&ioloop);

	lib_signals_deinit();

	test_assert(!tctx.timed_out);
	test_assert(tctx.signal_handled);

	test_end();

	test_begin("lib-signals delayed - init ioloop first");

	i_zero(&tctx);

	ioloop = io_loop_create();

	lib_signals_init();
	lib_signals_set_handler(SIGALRM,
		LIBSIG_FLAGS_SAFE | LIBSIG_FLAG_IOLOOP_AUTOMOVE,
		signal_handler_delayed, &tctx);

	to_kill = timeout_add_short(200, kill_timeout, &tctx);
	to_test = timeout_add_short(400, test_timeout, &tctx);
	io_loop_run(ioloop);

	timeout_remove(&to_kill);
	timeout_remove(&to_test);

	lib_signals_deinit();

	io_loop_destroy(&ioloop);

	test_assert(!tctx.timed_out);
	test_assert(tctx.signal_handled);

	test_end();

}

static void
test_lib_signals_delayed_nested_ioloop(void)
{
	struct test_context_delayed tctx;
	struct timeout *to_kill, *to_test;
	struct ioloop *ioloop1, *ioloop2;

	test_begin("lib-signals delayed in nested ioloop");

	i_zero(&tctx);

	lib_signals_init();
	lib_signals_set_handler(SIGALRM,
		LIBSIG_FLAGS_SAFE | LIBSIG_FLAG_IOLOOP_AUTOMOVE,
		signal_handler_delayed, &tctx);

	/* briefly run outer ioloop */
	ioloop1 = io_loop_create();
	to_test = timeout_add_short(100, test_timeout, &tctx);
	io_loop_run(ioloop1);
	timeout_remove(&to_test);
	test_assert(tctx.timed_out);
	test_assert(!tctx.signal_handled);
	tctx.timed_out = FALSE;

	/* run inner ioloop, which triggers the signal */
	ioloop2 = io_loop_create();
	to_kill = timeout_add_short(200, kill_timeout, &tctx);
	to_test = timeout_add_short(400, test_timeout, &tctx);
	io_loop_run(ioloop2);

	timeout_remove(&to_kill);
	timeout_remove(&to_test);
	io_loop_destroy(&ioloop2);

	io_loop_destroy(&ioloop1);

	lib_signals_deinit();

	test_assert(!tctx.timed_out);
	test_assert(tctx.signal_handled);

	test_end();
}

static void
test_lib_signals_delayed_no_ioloop_automove(void)
{
	struct test_context_delayed tctx;
	struct timeout *to_kill, *to_test;
	struct ioloop *ioloop1, *ioloop2;

	test_begin("lib-signals delayed with NO_IOLOOP_AUTOMOVE - unmoved");

	i_zero(&tctx);

	ioloop1 = io_loop_create();

	lib_signals_init();
	lib_signals_set_handler(SIGALRM, LIBSIG_FLAGS_SAFE,
		signal_handler_delayed, &tctx);

	/* briefly run outer ioloop */
	to_test = timeout_add_short(100, test_timeout, &tctx);
	io_loop_run(ioloop1);
	timeout_remove(&to_test);
	test_assert(tctx.timed_out);
	test_assert(!tctx.signal_handled);
	tctx.timed_out = FALSE;

	/* run inner ioloop, which triggers the signal but musn't handle it */
	ioloop2 = io_loop_create();
	to_kill = timeout_add_short(200, kill_timeout, &tctx);
	to_test = timeout_add_short(400, test_timeout, &tctx);
	io_loop_run(ioloop2);

	test_assert(tctx.timed_out);
	test_assert(!tctx.signal_handled);
	tctx.timed_out = FALSE;

	timeout_remove(&to_kill);
	timeout_remove(&to_test);
	io_loop_destroy(&ioloop2);

	/* run outer ioloop once more */
	to_test = timeout_add_short(100, test_timeout, &tctx);
	io_loop_run(ioloop1);
	timeout_remove(&to_test);

	lib_signals_deinit();

	io_loop_destroy(&ioloop1);

	test_assert(!tctx.timed_out);
	test_assert(tctx.signal_handled);

	test_end();

	test_begin("lib-signals delayed with NO_IOLOOP_AUTOMOVE - moved");

	i_zero(&tctx);

	ioloop1 = io_loop_create();

	lib_signals_init();
	lib_signals_set_handler(SIGALRM, LIBSIG_FLAGS_SAFE,
		signal_handler_delayed, &tctx);

	/* briefly run outer ioloop */
	to_test = timeout_add_short(100, test_timeout, &tctx);
	io_loop_run(ioloop1);
	timeout_remove(&to_test);
	test_assert(tctx.timed_out);
	test_assert(!tctx.signal_handled);
	tctx.timed_out = FALSE;

	/* run inner ioloop, which triggers the signal */
	ioloop2 = io_loop_create();
	lib_signals_switch_ioloop(SIGALRM,
		signal_handler_delayed, &tctx);

	to_kill = timeout_add_short(200, kill_timeout, &tctx);
	to_test = timeout_add_short(400, test_timeout, &tctx);
	io_loop_run(ioloop2);

	test_assert(!tctx.timed_out);
	test_assert(tctx.signal_handled);

	timeout_remove(&to_kill);
	timeout_remove(&to_test);
	io_loop_destroy(&ioloop2);

	lib_signals_deinit();
	io_loop_destroy(&ioloop1);

	test_end();
}


void test_lib_signals(void)
{
	test_lib_signals_delayed();
	test_lib_signals_delayed_nested_ioloop();
	test_lib_signals_delayed_no_ioloop_automove();
}
