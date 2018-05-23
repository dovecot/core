/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "str.h"
#include "istream.h"
#include "istream-multiplex.h"
#include "ostream.h"
#include "ostream-multiplex.h"
#include "ostream.h"
#include "randgen.h"

#include <unistd.h>

struct test_channel {
	int fds[2];
	unsigned int cid;

	struct istream *in;
	struct ostream *out;
	struct io *io;

	struct istream *in_alt;
	struct ostream *out_alt;
	struct io *io_alt;

	buffer_t *received;
	buffer_t *received_alt;

	unsigned int counter;
};

static struct test_channel test_channel[2];

static void test_multiplex_channel_write(struct test_channel *channel)
{
	unsigned char buf[128];
	size_t len = i_rand() % sizeof(buf);
	random_fill(buf, len);
	o_stream_nsend(channel->out, buf, len);
	o_stream_nsend(channel->out_alt, buf, len);
}

static void test_multiplex_stream_write(struct ostream *channel ATTR_UNUSED)
{
	if (test_channel[0].received->used > 1000 &&
	    test_channel[1].received->used > 1000)
		io_loop_stop(current_ioloop);
	else
		test_multiplex_channel_write(&test_channel[i_rand() % 2]);
}

static void test_istream_multiplex_stream_read(struct test_channel *channel)
{
	const unsigned char *data = NULL;
	size_t siz = 0;

	if (i_stream_read(channel->in) > 0) {
		data = i_stream_get_data(channel->in, &siz);
		buffer_append(channel->received, data, siz);
		i_stream_skip(channel->in, siz);
	}
}

static void test_istream_read_alt(struct test_channel *channel)
{
	const unsigned char *data = NULL;
	size_t siz = 0;

	if (i_stream_read(channel->in_alt) > 0) {
		data = i_stream_get_data(channel->in_alt, &siz);
		buffer_append(channel->received_alt, data, siz);
		i_stream_skip(channel->in_alt, siz);
	}
}

static void setup_channel(struct test_channel *channel,
			  struct istream *is, struct ostream *os)
{
	/* setup first channel */
	channel->in = is;
	channel->out = os;
	channel->io = io_add_istream(is, test_istream_multiplex_stream_read,
				     channel);
	test_assert(pipe(channel->fds) == 0);
	fd_set_nonblock(channel->fds[0], TRUE);
	fd_set_nonblock(channel->fds[1], TRUE);
	channel->in_alt = i_stream_create_fd(channel->fds[0], (size_t)-1);
	channel->out_alt = o_stream_create_fd(channel->fds[1], IO_BLOCK_SIZE);
	channel->io_alt = io_add_istream(channel->in_alt, test_istream_read_alt,
					 channel);
	channel->received = buffer_create_dynamic(default_pool, 32768);
	channel->received_alt = buffer_create_dynamic(default_pool, 32768);
}

static void teardown_channel(struct test_channel *channel)
{
	test_istream_read_alt(channel);
	test_assert(memcmp(channel->received->data,
			   channel->received_alt->data,
			   channel->received->used) == 0);
	test_assert(channel->received->used == channel->received_alt->used);

	buffer_free(&channel->received);
	buffer_free(&channel->received_alt);

	io_remove(&channel->io);
	io_remove(&channel->io_alt);
	i_stream_unref(&channel->in);
	test_assert(o_stream_finish(channel->out) > 0);
	o_stream_unref(&channel->out);
	i_stream_unref(&channel->in_alt);
	test_assert(o_stream_finish(channel->out_alt) > 0);
	o_stream_unref(&channel->out_alt);
	i_close_fd(&channel->fds[0]);
	i_close_fd(&channel->fds[1]);
}

static void test_multiplex_stream(void) {
	test_begin("test multiplex (stream)");

	struct ioloop *ioloop = io_loop_create();
	io_loop_set_current(ioloop);

	int fds[2];
	test_assert(pipe(fds) == 0);
	fd_set_nonblock(fds[0], TRUE);
	fd_set_nonblock(fds[1], TRUE);
	struct ostream *os = o_stream_create_fd(fds[1], (size_t)-1);
	struct istream *is = i_stream_create_fd(fds[0], (size_t)-1);

	struct istream *ichan0 = i_stream_create_multiplex(is, (size_t)-1);
	struct istream *ichan1 = i_stream_multiplex_add_channel(ichan0, 1);
	i_stream_unref(&is);

	struct ostream *ochan0 = o_stream_create_multiplex(os, 1024);
	struct ostream *ochan1 = o_stream_multiplex_add_channel(ochan0, 1);
	o_stream_unref(&os);

	struct io *io = io_add(fds[1], IO_WRITE, test_multiplex_stream_write, os);

	setup_channel(&test_channel[0], ichan0, ochan0);
	setup_channel(&test_channel[1], ichan1, ochan1);

	test_channel[0].cid = 0;
	test_channel[1].cid = 1;

	io_loop_run(current_ioloop);

	io_remove(&io);

	teardown_channel(&test_channel[0]);
	teardown_channel(&test_channel[1]);

	io_loop_destroy(&ioloop);

	i_close_fd(&fds[0]);
	i_close_fd(&fds[1]);

	test_end();
}

void test_multiplex(void) {
	random_init();
	test_multiplex_stream();
	random_deinit();
}
