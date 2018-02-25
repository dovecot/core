/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "ostream.h"
#include "buffer.h"
#include "str.h"
#include "ioloop.h"
#include "iostream-pump.h"
#include "istream-failure-at.h"
#include "ostream-failure-at.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

struct nonblock_ctx {
	struct istream *in;
	struct ostream *out;
	uoff_t pos, max_size;
};

static unsigned char data[] = "hello, world";

static void completed(enum iostream_pump_status status, int *u0)
{
	/* to somehow discern between error and success .. */
	(*u0) -= (status == IOSTREAM_PUMP_STATUS_INPUT_EOF ? 1 : 2);
	io_loop_stop(current_ioloop);
}

static void failed(int *u0)
{
	*u0 = -1; /* ensure failure */
	io_loop_stop(current_ioloop);
}

static void pump_nonblocking_timeout(struct nonblock_ctx *ctx)
{
	switch (ctx->pos % 4) {
	case 0:
		break;
	case 1:
		/* allow more input */
		if (ctx->pos/4 == ctx->max_size+1)
			test_istream_set_allow_eof(ctx->in, TRUE);
		else
			test_istream_set_size(ctx->in, ctx->pos/4);
		i_stream_set_input_pending(ctx->in, TRUE);
		break;
	case 2:
		break;
	case 3: {
		/* allow more output. give always one byte less than the
		   input size so there's something in internal buffer. */
		size_t size = ctx->pos/4;
		if (size > 0)
			test_ostream_set_max_output_size(ctx->out, size-1);
		break;
	}
	}
	ctx->pos++;
}

static const char *
run_pump(struct istream *in, struct ostream *out, int *counter,
	 buffer_t *out_buffer)
{
	struct iostream_pump *pump;
	struct ioloop *ioloop = io_loop_create();
	io_loop_set_current(ioloop);
	struct nonblock_ctx ctx = { in, out, 0, 0 };
	struct timeout *to2 = NULL;

	if (!in->blocking) {
		test_assert(i_stream_get_size(in, TRUE, &ctx.max_size) > 0);
		test_istream_set_size(in, 0);
		test_istream_set_allow_eof(in, FALSE);
		test_ostream_set_max_output_size(out, 0);
		to2 = timeout_add_short(0, pump_nonblocking_timeout, &ctx);
	}

	pump = iostream_pump_create(in, out);
	i_stream_unref(&in);
	o_stream_unref(&out);

	iostream_pump_set_completion_callback(pump, completed, counter);
	iostream_pump_start(pump);

	alarm(5);
	struct timeout *to = timeout_add(3000, failed, counter);

	io_loop_run(current_ioloop);

	timeout_remove(&to);
	timeout_remove(&to2);
	alarm(0);

	test_assert(*counter == 0);

	if (!ctx.in->blocking && ctx.in->stream_errno != 0 &&
	    ctx.out->stream_errno == 0) {
		/* input failed, finish flushing output */
		test_ostream_set_max_output_size(ctx.out, (size_t)-1);
		test_assert(o_stream_flush(ctx.out) > 0);
	} else {
		test_assert(o_stream_flush(ctx.out) != 0);
	}

	const char *ret = t_strdup(str_c(out_buffer));

	iostream_pump_unref(&pump);
	io_loop_destroy(&ioloop);

	return ret;
}

static void
test_iostream_setup(bool block, struct istream **in_r,
		    struct ostream **out_r, buffer_t **out_buffer_r)
{
	*out_buffer_r = t_buffer_create(128);

	*in_r = test_istream_create_data(data, sizeof(data));
	(*in_r)->blocking = block;

	if (block)
		*out_r = test_ostream_create(*out_buffer_r);
	else
		*out_r = test_ostream_create_nonblocking(*out_buffer_r, 1);
}

static void
test_iostream_pump_simple(bool block)
{
	int counter;
	struct istream *in;
	struct ostream *out;
	buffer_t *buffer;

	test_begin(t_strdup_printf("iostream_pump (%sblocking)",
				   block ? "" : "non-"));

	test_iostream_setup(block, &in, &out, &buffer);
	counter = 1;

	test_assert(strcmp(run_pump(in, out, &counter, buffer),
			   "hello, world") == 0);

	test_end();
}

static void
test_iostream_pump_failure_start_read(bool block)
{
	int counter;
	struct istream *in, *in_2;
	struct ostream *out;
	buffer_t *buffer;

	test_begin(t_strdup_printf("iostream_pump failure start-read "
				   "(%sblocking)", block ? "" : "non-"));

	test_iostream_setup(block, &in_2, &out, &buffer);
	in = i_stream_create_failure_at(in_2, 0, EIO, "test pump fail");
	i_stream_unref(&in_2);
	counter = 2;
	test_assert(strcmp(run_pump(in, out, &counter, buffer), "") == 0);

	test_end();
}

static void
test_iostream_pump_failure_mid_read(bool block)
{
	int counter;
	struct istream *in, *in_2;
	struct ostream *out;
	buffer_t *buffer;

	test_begin(t_strdup_printf("iostream_pump failure mid-read "
				   "(%sblocking)", block ? "" : "non-"));

	test_iostream_setup(block, &in_2, &out, &buffer);
	in = i_stream_create_failure_at(in_2, 4, EIO, "test pump fail");
	i_stream_unref(&in_2);
	counter = 2;
	test_assert(strcmp(run_pump(in, out, &counter, buffer), "hell") == 0);

	test_end();
}

static void
test_iostream_pump_failure_end_read(bool block)
{
	int counter;
	struct istream *in, *in_2;
	struct ostream *out;
	buffer_t *buffer;

	test_begin(t_strdup_printf("iostream_pump failure mid-read "
		   "(%sblocking)", block ? "" : "non-"));

	test_iostream_setup(block, &in_2, &out, &buffer);
	in = i_stream_create_failure_at_eof(in_2, EIO, "test pump fail");
	i_stream_unref(&in_2);
	counter = 2;
	test_assert(strcmp(run_pump(in, out, &counter, buffer),
		    "hello, world") == 0);

	test_end();
}

static void
test_iostream_pump_failure_start_write(bool block)
{
	int counter;
	struct istream *in;
	struct ostream *out, *out_2;
	buffer_t *buffer;

	test_begin(t_strdup_printf("iostream_pump failure start-write "
				   "(%sblocking)", block ? "" : "non-"));

	test_iostream_setup(block, &in, &out_2, &buffer);
	out = o_stream_create_failure_at(out_2, 0, "test pump fail");
	o_stream_unref(&out_2);
	counter = 2;
	test_assert(strcmp(run_pump(in, out, &counter, buffer), "") == 0);

	test_end();
}

static void
test_iostream_pump_failure_mid_write(bool block)
{
	int counter;
	struct istream *in;
	struct ostream *out, *out_2;
	buffer_t *buffer;

	test_begin(t_strdup_printf("iostream_pump failure mid-write "
				   "(%sblocking)", block ? "" : "non-"));

	test_iostream_setup(block, &in, &out_2, &buffer);
	out = o_stream_create_failure_at(out_2, 4, "test pump fail");
	o_stream_unref(&out_2);
	counter = 2;

	/* "hel" because the last byte is only in internal buffer */
	test_assert(strcmp(run_pump(in, out, &counter, buffer),
		           (block ? "" : "hel")) == 0);

	test_end();
}

static void
test_iostream_pump_failure_end_write(bool block)
{
	int counter;
	struct istream *in;
	struct ostream *out, *out_2;
	buffer_t *buffer;

	if (!block) {
		/* we'll get flushes constantly */
		return;
	}

	test_begin("iostream_pump failure end-write (blocking)");

	test_iostream_setup(block, &in, &out_2, &buffer);
	out = o_stream_create_failure_at_flush(out_2, "test pump fail");
	o_stream_unref(&out_2);
	counter = 2;
	test_assert(strcmp(run_pump(in, out, &counter, buffer),
			   "hello, world") == 0);

	test_end();
}

void test_iostream_pump(void)
{
	T_BEGIN {
		for(int i = 0; i < 2; i++) {
			test_iostream_pump_simple(i < 1);
			test_iostream_pump_failure_start_read(i < 1);
			test_iostream_pump_failure_mid_read(i < 1);
			test_iostream_pump_failure_end_read(i < 1);
			test_iostream_pump_failure_start_write(i < 1);
			test_iostream_pump_failure_mid_write(i < 1);
			test_iostream_pump_failure_end_write(i < 1);
		}
	} T_END;
}
