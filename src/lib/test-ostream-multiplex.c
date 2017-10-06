/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "randgen.h"
#include "ioloop.h"
#include "fd-set-nonblock.h"
#include "str.h"
#include "istream.h"
#include "ostream-private.h"
#include "ostream-multiplex.h"
#include "ostream.h"
#include <unistd.h>

#include "hex-binary.h"

static void test_ostream_multiplex_simple(void)
{
	test_begin("ostream multiplex (simple)");

	const unsigned char expected[] = {
		'\x00','\x00','\x00','\x00','\x05','\x68','\x65',
		'\x6c','\x6c','\x6f','\x01','\x00','\x00','\x00',
		'\x05','\x77','\x6f','\x72','\x6c','\x64'
	};

	buffer_t *result = t_str_new(64);
	struct ostream *os = test_ostream_create(result);
	struct ostream *os2 = o_stream_create_multiplex(os, (size_t)-1);
	struct ostream *os3 = o_stream_multiplex_add_channel(os2, 1);

	test_assert(o_stream_send_str(os2, "hello") == 5);
	test_assert(o_stream_send_str(os3, "world") == 5);

	o_stream_unref(&os3);
	o_stream_unref(&os2);
	o_stream_unref(&os);

	test_assert(sizeof(expected) == result->used);
	test_assert(memcmp(result->data, expected, I_MIN(sizeof(expected),
		    result->used)) == 0);

	test_end();
}

static unsigned int channel_counter[2] = {0, 0};
static struct ostream *chan0, *chan1;

static const char *msgs[] = {
	"",
	"a",
	"bb",
	"ccc",
	"dddd",
	"eeeee",
	"ffffff"
};

static void test_ostream_multiplex_stream_read(struct istream *is)
{
	uint8_t cid;
	const unsigned char *data;
	size_t siz,dlen=0,pos=0;

	if (i_stream_read_more(is, &data, &siz)>0) {
		/* parse stream */
		for(;pos<siz;) {
			if (dlen > 0) {
				if (dlen < N_ELEMENTS(msgs)) {
					test_assert_idx(memcmp(&data[pos],
							       msgs[dlen], dlen)==0,
							channel_counter[data[0] % 2]);
				}
				channel_counter[data[0] % 2]++;
				pos += dlen;
				dlen = 0;
			} else if (dlen == 0) {
				cid = data[pos] % 2;
				test_assert_idx(data[pos] < 2, channel_counter[cid]);
				pos++;
				dlen = be32_to_cpu_unaligned(&data[pos]);
				pos += 4;
				test_assert(dlen > 0 && dlen < N_ELEMENTS(msgs));
			}
		}
		i_stream_skip(is, siz);
	}

	if (channel_counter[0] > 100 && channel_counter[1] > 100)
		io_loop_stop(current_ioloop);
}

static void test_ostream_multiplex_stream_write(struct ostream *channel ATTR_UNUSED)
{
	size_t rounds = 1 + rand() % 10;
	for(size_t i = 0; i < rounds; i++) {
		if ((rand() % 2) != 0)
			o_stream_nsend_str(chan1, msgs[rand() % N_ELEMENTS(msgs)]);
		else
			o_stream_nsend_str(chan0, msgs[rand() % N_ELEMENTS(msgs)]);
	}
}

static void test_ostream_multiplex_stream(void)
{
	test_begin("ostream multiplex (stream)");

	struct ioloop *ioloop = io_loop_create();
	io_loop_set_current(ioloop);

	int fds[2];
	test_assert(pipe(fds) == 0);
	fd_set_nonblock(fds[0], TRUE);
	fd_set_nonblock(fds[1], TRUE);
	struct ostream *os = o_stream_create_fd(fds[1], (size_t)-1, FALSE);
	struct istream *is = i_stream_create_fd(fds[0], (size_t)-1, FALSE);

	chan0 = o_stream_create_multiplex(os, (size_t)-1);
	chan1 = o_stream_multiplex_add_channel(chan0, 1);

	struct io *io0 =
		io_add_istream(is, test_ostream_multiplex_stream_read, is);
	struct io *io1 =
		io_add(fds[1], IO_WRITE, test_ostream_multiplex_stream_write, os);

	io_loop_run(current_ioloop);

	io_remove(&io0);
	io_remove(&io1);

	test_assert(o_stream_nfinish(chan1) == 0);
	o_stream_unref(&chan1);
	test_assert(o_stream_nfinish(chan0) == 0);
	o_stream_unref(&chan0);

	i_stream_unref(&is);
	o_stream_unref(&os);

	io_loop_destroy(&ioloop);

	i_close_fd(&fds[0]);
	i_close_fd(&fds[1]);

	test_end();
}

void test_ostream_multiplex(void)
{
	random_init();
	test_ostream_multiplex_simple();
	test_ostream_multiplex_stream();
	random_deinit();
}
