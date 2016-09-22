/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "net.h"
#include "time-util.h"
#include "ioloop.h"
#include "istream.h"

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

static void io_callback(void *context ATTR_UNUSED)
{
}

static void test_ioloop_find_fd_conditions(void)
{
	struct {
		enum io_condition condition;
		int fd[2];
		struct io *io;
	} tests[] = {
		{ IO_ERROR, { -1, -1 }, NULL },
		{ IO_READ, { -1, -1 }, NULL },
		{ IO_WRITE, { -1, -1 }, NULL },
		{ IO_READ | IO_WRITE, { -1, -1 }, NULL },
		{ IO_READ, { -1, -1 }, NULL } /* read+write as separate ios */
	};
	struct ioloop *ioloop;
	struct io *io;
	unsigned int i;

	test_begin("ioloop find fd conditions");

	ioloop = io_loop_create();

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, tests[i].fd) < 0)
			i_fatal("socketpair() failed: %m");
		tests[i].io = io_add(tests[i].fd[0], tests[i].condition, io_callback, (void *)NULL);
	}
	io = io_add(tests[i-1].fd[0], IO_WRITE, io_callback, (void *)NULL);
	tests[i-1].condition |= IO_WRITE;

	for (i = 0; i < N_ELEMENTS(tests); i++)
		test_assert_idx(io_loop_find_fd_conditions(ioloop, tests[i].fd[0]) == tests[i].condition, i);

	io_remove(&io);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		io_remove(&tests[i].io);
		i_close_fd(&tests[i].fd[0]);
		i_close_fd(&tests[i].fd[1]);
	}
	io_loop_destroy(&ioloop);

	test_end();
}

static void io_callback_pending_io(void *context ATTR_UNUSED)
{
	io_loop_stop(current_ioloop);
}

static void test_ioloop_pending_io(void)
{
	test_begin("ioloop pending io");

	struct istream *is = i_stream_create_from_data("data", 4);
	struct ioloop *ioloop = io_loop_create();
	struct io *io = io_add_istream(is, io_callback_pending_io, NULL);
	io_loop_set_current(ioloop);
	io_set_pending(io);
	io_loop_run(ioloop);
	io_remove(&io);
	i_stream_unref(&is);
	io_loop_destroy(&ioloop);

	test_end();
}

void test_ioloop(void)
{
	test_ioloop_timeout();
	test_ioloop_find_fd_conditions();
	test_ioloop_pending_io();
}
