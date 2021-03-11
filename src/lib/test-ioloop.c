/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "net.h"
#include "time-util.h"
#include "ioloop.h"
#include "istream.h"

#include <unistd.h>

struct test_ctx {
	bool got_left;
	bool got_right;
	bool got_to;
};

static void timeout_callback(struct timeval *tv)
{
	i_gettimeofday(tv);
	io_loop_stop(current_ioloop);
}

static void test_ioloop_fd_cb_left(struct test_ctx *ctx)
{
	ctx->got_left = TRUE;
	if (ctx->got_left && ctx->got_right)
		io_loop_stop(current_ioloop);
}

static void test_ioloop_fd_cb_right(struct test_ctx *ctx)
{
	ctx->got_right = TRUE;
	if (ctx->got_left && ctx->got_right)
		io_loop_stop(current_ioloop);
}

static void test_ioloop_fd_to(struct test_ctx *ctx)
{
	ctx->got_to = TRUE;
	io_loop_stop(current_ioloop);
}

static void test_ioloop_fd(void)
{
	test_begin("ioloop fd");

	struct test_ctx test_ctx;
	int fds[2];
	int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	test_assert(ret == 0);
	if (ret < 0) {
		i_error("socketpair() failed: %m");
		test_end();
		return;
	}

	i_zero(&test_ctx);

	struct ioloop *ioloop = io_loop_create();

	struct io *io_left =
			io_add(fds[0], IO_READ,
			       test_ioloop_fd_cb_left, &test_ctx);
	struct io *io_right =
			io_add(fds[1], IO_READ,
				test_ioloop_fd_cb_right, &test_ctx);

	struct timeout *to = timeout_add(2000, test_ioloop_fd_to, &test_ctx);

	if (write(fds[0], "ltr", 3) != 3 ||
	    write(fds[1], "rtl", 3) != 3)
		i_fatal("write() failed: %m");

	io_loop_run(ioloop);

	timeout_remove(&to);
	io_remove(&io_left);
	io_remove(&io_right);

	test_assert(test_ctx.got_to == FALSE);
	test_assert(test_ctx.got_left == TRUE);
	test_assert(test_ctx.got_right == TRUE);

	io_loop_destroy(&ioloop);
	i_close_fd(&fds[0]);
	i_close_fd(&fds[1]);

	test_end();
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
	test_assert(io_loop_is_empty(ioloop));
	test_assert(io_loop_is_empty(ioloop2));
	to2 = timeout_add(1000, timeout_callback, &tv_callback);
	test_assert(io_loop_is_empty(ioloop));
	test_assert(!io_loop_is_empty(ioloop2));
	io_loop_set_current(ioloop);
	to2 = io_loop_move_timeout(&to2);
	test_assert(!io_loop_is_empty(ioloop));
	test_assert(io_loop_is_empty(ioloop2));
	io_loop_set_current(ioloop2);
	io_loop_destroy(&ioloop2);

	sleep(1);

	/* add & remove immediately */
	to = timeout_add(1000, timeout_callback, &tv_callback);
	timeout_remove(&to);

	/* add the timeout we're actually testing below */
	to = timeout_add(1000, timeout_callback, &tv_callback);
	i_gettimeofday(&tv_start);
	io_loop_run(ioloop);
	test_assert(timeval_diff_msecs(&tv_callback, &tv_start) >= 500);
	timeout_remove(&to);
	timeout_remove(&to2);
	test_assert(io_loop_is_empty(ioloop));
	io_loop_destroy(&ioloop);

	test_end();
}

static void zero_timeout_callback(unsigned int *counter)
{
	*counter += 1;
}

static void test_ioloop_zero_timeout(void)
{
	struct ioloop *ioloop;
	struct timeout *to;
	struct io *io;
	unsigned int counter = 0;
	int fd[2];

	test_begin("ioloop zero timeout");

	if (pipe(fd) < 0)
		i_fatal("pipe() failed: %m");
	switch (fork()) {
	case (pid_t)-1:
		i_fatal("fork() failed: %m");
	case 0:
		sleep(1);
		char c = 0;
		if (write(fd[1], &c, 1) < 0)
			i_fatal("write(pipe) failed: %m");
		test_exit(0);
	default:
		break;
	}

	ioloop = io_loop_create();
	to = timeout_add_short(0, zero_timeout_callback, &counter);
	io = io_add(fd[0], IO_READ, io_loop_stop, ioloop);

	io_loop_run(ioloop);
	test_assert_ucmp(counter, >, 1000);

	timeout_remove(&to);
	io_remove(&io);
	io_loop_destroy(&ioloop);
	test_end();
}

struct zero_timeout_recreate_ctx {
	struct timeout *to;
	unsigned int counter;
};

static void
zero_timeout_recreate_callback(struct zero_timeout_recreate_ctx *ctx)
{
	timeout_remove(&ctx->to);
	ctx->to = timeout_add_short(0, zero_timeout_recreate_callback, ctx);
	ctx->counter++;
}

static void test_ioloop_zero_timeout_recreate(void)
{
	struct ioloop *ioloop;
	struct io *io;
	struct zero_timeout_recreate_ctx ctx = { .counter = 0 };
	int fd[2];

	test_begin("ioloop zero timeout recreate");

	if (pipe(fd) < 0)
		i_fatal("pipe() failed: %m");
	switch (fork()) {
	case (pid_t)-1:
		i_fatal("fork() failed: %m");
	case 0:
		sleep(1);
		char c = 0;
		if (write(fd[1], &c, 1) < 0)
			i_fatal("write(pipe) failed: %m");
		test_exit(0);
	default:
		break;
	}

	ioloop = io_loop_create();
	ctx.to = timeout_add_short(0, zero_timeout_recreate_callback, &ctx);
	io = io_add(fd[0], IO_READ, io_loop_stop, ioloop);

	io_loop_run(ioloop);
	test_assert_ucmp(ctx.counter, >, 1000);

	timeout_remove(&ctx.to);
	io_remove(&io);
	io_loop_destroy(&ioloop);
	test_end();
}

static void io_callback(void *context ATTR_UNUSED)
{
}

static void test_ioloop_find_fd_conditions(void)
{
	static struct {
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
		tests[i].io = io_add(tests[i].fd[0], tests[i].condition, io_callback, NULL);
	}
	io = io_add(tests[i-1].fd[0], IO_WRITE, io_callback, NULL);
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
	test_assert(io_loop_is_empty(ioloop));
	struct io *io = io_add_istream(is, io_callback_pending_io, NULL);
	test_assert(!io_loop_is_empty(ioloop));
	io_loop_set_current(ioloop);
	io_set_pending(io);
	io_loop_run(ioloop);
	io_remove(&io);
	i_stream_unref(&is);
	io_loop_destroy(&ioloop);

	test_end();
}

static void test_ioloop_context_callback(struct ioloop_context *ctx)
{
	test_assert(io_loop_get_current_context(current_ioloop) == ctx);
	io_loop_stop(current_ioloop);
}

static void test_ioloop_context(void)
{
	test_begin("ioloop context");
	struct ioloop *ioloop = io_loop_create();
	struct ioloop_context *ctx = io_loop_context_new(ioloop);

	test_assert(io_loop_get_current_context(current_ioloop) == NULL);
	io_loop_context_activate(ctx);
	test_assert(io_loop_get_current_context(current_ioloop) == ctx);
	struct timeout *to = timeout_add(0, test_ioloop_context_callback, ctx);

	io_loop_run(ioloop);
	test_assert(io_loop_get_current_context(current_ioloop) == NULL);
	/* test that we don't crash at deinit if we leave the context active */
	io_loop_context_activate(ctx);
	test_assert(io_loop_get_current_context(current_ioloop) == ctx);

	timeout_remove(&to);
	io_loop_context_unref(&ctx);
	io_loop_destroy(&ioloop);
	test_end();
}

static void test_ioloop_context_events_run(struct event *root_event)
{
	struct ioloop *ioloop = io_loop_create();
	struct ioloop_context *ctx1, *ctx2;

	/* create context 1 */
	ctx1 = io_loop_context_new(ioloop);
	io_loop_context_switch(ctx1);
	struct event *ctx1_event1 = event_create(NULL);
	event_push_global(ctx1_event1);
	struct event *ctx1_event2 = event_create(NULL);
	event_push_global(ctx1_event2);
	io_loop_context_deactivate(ctx1);

	test_assert(event_get_global() == root_event);

	/* create context 2 */
	ctx2 = io_loop_context_new(ioloop);
	io_loop_context_switch(ctx2);
	struct event *ctx2_event1 = event_create(NULL);
	event_push_global(ctx2_event1);
	io_loop_context_deactivate(ctx2);

	test_assert(event_get_global() == root_event);

	/* test switching contexts */
	io_loop_context_switch(ctx1);
	test_assert(event_get_global() == ctx1_event2);
	io_loop_context_switch(ctx2);
	test_assert(event_get_global() == ctx2_event1);

	/* test popping away events */
	io_loop_context_switch(ctx1);
	event_pop_global(ctx1_event2);
	io_loop_context_switch(ctx2);
	event_pop_global(ctx2_event1);
	io_loop_context_switch(ctx1);
	test_assert(event_get_global() == ctx1_event1);
	io_loop_context_switch(ctx2);
	test_assert(event_get_global() == root_event);

	io_loop_context_deactivate(ctx2);
	io_loop_context_unref(&ctx1);
	io_loop_context_unref(&ctx2);
	io_loop_destroy(&ioloop);

	event_unref(&ctx1_event1);
	event_unref(&ctx1_event2);
	event_unref(&ctx2_event1);
}

static void test_ioloop_context_events(void)
{
	test_begin("ioloop context - no root event");
	test_ioloop_context_events_run(NULL);
	test_end();

	test_begin("ioloop context - with root event");
	struct event *root_event = event_create(NULL);
	event_push_global(root_event);
	test_ioloop_context_events_run(root_event);
	event_pop_global(root_event);
	event_unref(&root_event);
	test_end();
}

void test_ioloop(void)
{
	test_ioloop_timeout();
	test_ioloop_zero_timeout();
	test_ioloop_zero_timeout_recreate();
	test_ioloop_find_fd_conditions();
	test_ioloop_pending_io();
	test_ioloop_fd();
	test_ioloop_context();
	test_ioloop_context_events();
}
