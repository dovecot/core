/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "time-util.h"
#include "ioloop.h"

#include <unistd.h>

static void timeout_callback(struct timeval *tv)
{
	if (gettimeofday(tv, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");
	io_loop_stop(current_ioloop);
}

static void test_ioloop_timeout(void)
{
	struct ioloop *ioloop, *ioloop2;
	struct timeout *to, *to2;
	struct timeval tv_start, tv_callback;

	test_begin("ioloop timeout");

	ioloop = io_loop_create();

	/* add a timeout by moving it from another ioloop */
	ioloop2 = io_loop_create();
	to2 = timeout_add(1000, timeout_callback, &tv_callback);
	io_loop_set_current(ioloop);
	to2 = io_loop_move_timeout(&to2);
	io_loop_set_current(ioloop2);
	io_loop_destroy(&ioloop2);

	sleep(1);

	/* add & remove immediately */
	to = timeout_add(1000, timeout_callback, &tv_callback);
	timeout_remove(&to);

	/* add the timeout we're actually testing below */
	to = timeout_add(1000, timeout_callback, &tv_callback);
	if (gettimeofday(&tv_start, NULL) < 0)
		i_fatal("gettimeofday() failed: %m");
	io_loop_run(ioloop);
	test_assert(timeval_diff_msecs(&tv_callback, &tv_start) >= 500);
	timeout_remove(&to);
	timeout_remove(&to2);
	io_loop_destroy(&ioloop);

	test_end();
}

void test_ioloop(void)
{
	test_ioloop_timeout();
}
