/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "ostream.h"
#include "buffer.h"
#include "ioloop.h"
#include "iostream-proxy.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

static
void completed(enum iostream_proxy_side side ATTR_UNUSED,
	       enum iostream_proxy_status status ATTR_UNUSED, int *u0)
{
	i_assert(*u0 > 0);
	if (--*u0 == 0)
		io_loop_stop(current_ioloop);
}

static
void test_iostream_proxy_simple(void)
{
	size_t bytes;

	test_begin("iostream_proxy");
	int sfdl[2];
	int sfdr[2];

	int counter;

	test_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sfdl) == 0);
	test_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sfdr) == 0);

	fd_set_nonblock(sfdl[0], TRUE);
	fd_set_nonblock(sfdl[1], TRUE);
	fd_set_nonblock(sfdr[0], TRUE);
	fd_set_nonblock(sfdr[1], TRUE);

	struct ioloop *ioloop = io_loop_create();

	struct istream *left_in = i_stream_create_fd(sfdl[1], IO_BLOCK_SIZE);
	struct ostream *left_out = o_stream_create_fd(sfdl[1], IO_BLOCK_SIZE);

	struct istream *right_in = i_stream_create_fd(sfdr[1], IO_BLOCK_SIZE);
	struct ostream *right_out = o_stream_create_fd(sfdr[1], IO_BLOCK_SIZE);

	struct iostream_proxy *proxy;

	proxy = iostream_proxy_create(left_in, left_out, right_in, right_out);
	i_stream_unref(&left_in);
	o_stream_unref(&left_out);
	i_stream_unref(&right_in);
	o_stream_unref(&right_out);

	iostream_proxy_set_completion_callback(proxy, completed, &counter);
	iostream_proxy_start(proxy);

	left_in = i_stream_create_fd(sfdl[0], IO_BLOCK_SIZE);
	left_out = o_stream_create_fd(sfdl[0], IO_BLOCK_SIZE);

	right_in = i_stream_create_fd(sfdr[0], IO_BLOCK_SIZE);
	right_out = o_stream_create_fd(sfdr[0], IO_BLOCK_SIZE);

	test_assert(proxy != NULL);
	test_assert(o_stream_send_str(left_out, "hello, world") > 0);
	test_assert(o_stream_flush(left_out) > 0);
	o_stream_unref(&left_out);
	test_assert(shutdown(sfdl[0], SHUT_WR) == 0);

	counter = 1;
	io_loop_run(ioloop);

	test_assert(i_stream_read(right_in) > 0);
	test_assert(strcmp((const char*)i_stream_get_data(right_in, &bytes), "hello, world") == 0);
	i_stream_skip(right_in, bytes);

	test_assert(o_stream_send_str(right_out, "hello, world") > 0);
	test_assert(o_stream_flush(right_out) > 0);
	o_stream_unref(&right_out);
	test_assert(shutdown(sfdr[0], SHUT_WR) == 0);

	counter = 1;
	io_loop_run(ioloop);

	test_assert(i_stream_read(left_in) > 0);
	test_assert(strcmp((const char*)i_stream_get_data(left_in, &bytes), "hello, world") == 0);
	i_stream_skip(left_in, bytes);

	iostream_proxy_unref(&proxy);

	io_loop_destroy(&ioloop);

	i_stream_unref(&left_in);
	i_stream_unref(&right_in);

	/* close fd */
	i_close_fd(&sfdl[0]);
	i_close_fd(&sfdl[1]);
	i_close_fd(&sfdr[0]);
	i_close_fd(&sfdr[1]);

	test_end();
}

void test_iostream_proxy(void)
{
	T_BEGIN {
		test_iostream_proxy_simple();
	} T_END;
}
