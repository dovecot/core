/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "str.h"
#include "istream.h"
#include "ostream-private.h"
#include "istream-multiplex.h"
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

	test_assert(o_stream_finish(os) == 1);
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
	size_t rounds = 1 + i_rand() % 10;
	for(size_t i = 0; i < rounds; i++) {
		if ((i_rand() % 2) != 0) {
			o_stream_cork(chan1);
			/* send one byte at a time */
			for(const char *p = msgs[i_rand() % N_ELEMENTS(msgs)];
			    *p != '\0'; p++) {
				o_stream_nsend(chan1, p, 1);
			}
			o_stream_uncork(chan1);
		} else {
			o_stream_nsend_str(chan0, msgs[i_rand() % N_ELEMENTS(msgs)]);
		}
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
	struct ostream *os = o_stream_create_fd(fds[1], (size_t)-1);
	struct istream *is = i_stream_create_fd(fds[0], (size_t)-1);

	chan0 = o_stream_create_multiplex(os, (size_t)-1);
	chan1 = o_stream_multiplex_add_channel(chan0, 1);

	struct io *io0 =
		io_add_istream(is, test_ostream_multiplex_stream_read, is);
	struct io *io1 =
		io_add(fds[1], IO_WRITE, test_ostream_multiplex_stream_write, os);

	io_loop_run(current_ioloop);

	io_remove(&io0);
	io_remove(&io1);

	test_assert(o_stream_finish(chan1) > 0);
	o_stream_unref(&chan1);
	test_assert(o_stream_finish(chan0) > 0);
	o_stream_unref(&chan0);

	i_stream_unref(&is);
	o_stream_unref(&os);

	io_loop_destroy(&ioloop);

	i_close_fd(&fds[0]);
	i_close_fd(&fds[1]);

	test_end();
}

static void test_ostream_multiplex_cork(void)
{
	test_begin("ostream multiplex (corking)");
	buffer_t *output = t_buffer_create(128);
	struct ostream *os = test_ostream_create(output);
	struct ostream *chan0 = o_stream_create_multiplex(os, (size_t)-1);

	const struct const_iovec iov[] = {
		{ "hello", 5 },
		{ " ", 1 },
		{ "world", 5 },
		{ "!", 1 }
	};

	/* send data in parts, expect to see single blob */
	o_stream_cork(chan0);
	o_stream_nsendv(chan0, iov, N_ELEMENTS(iov));
	o_stream_uncork(chan0);
	test_assert(o_stream_flush(os) == 1);

	/* check output */
	test_assert(memcmp(output->data, "\0\0\0\0\f", 5) == 0);
	test_assert(strcmp(str_c(output)+5, "hello world!") == 0);

	test_assert(o_stream_finish(chan0) > 0);
	o_stream_unref(&chan0);
	o_stream_unref(&os);

	test_end();
}

struct test_hang_context {
	struct istream *input1, *input2;
	size_t sent_bytes, sent2_bytes;
	size_t read_bytes, read2_bytes;
};

static void test_hang_input(struct test_hang_context *ctx)
{
	ssize_t ret, ret2;

	do {
		ret = i_stream_read(ctx->input1);
		if (ret > 0) {
			i_stream_skip(ctx->input1, ret);
			ctx->read_bytes += ret;
		}
		ret2 = i_stream_read(ctx->input2);
		if (ret2 > 0) {
			i_stream_skip(ctx->input2, ret2);
			ctx->read2_bytes += ret2;
		}
	} while (ret > 0 || ret2 > 0);

	test_assert(ret == 0 && ret2 == 0);
	if (ctx->read_bytes == ctx->sent_bytes &&
	    ctx->read2_bytes == ctx->sent2_bytes)
		io_loop_stop(current_ioloop);
}

static void test_ostream_multiplex_hang(void)
{
	int fd[2];

	test_begin("ostream multiplex hang");
	if (pipe(fd) < 0)
		i_fatal("pipe() failed: %m");
	fd_set_nonblock(fd[0], TRUE);
	fd_set_nonblock(fd[1], TRUE);

	struct ioloop *ioloop = io_loop_create();
	struct ostream *file_output = o_stream_create_fd(fd[1], 1024);
	o_stream_set_no_error_handling(file_output, TRUE);
	struct ostream *channel = o_stream_create_multiplex(file_output, 4096);
	struct ostream *channel2 = o_stream_multiplex_add_channel(channel, 1);
	char buf[256];

	/* send multiplex output until the buffer is full */
	ssize_t ret, ret2;
	size_t sent_bytes = 0, sent2_bytes = 0;
	i_zero(&buf);
	o_stream_cork(channel);
	o_stream_cork(channel2);
	while ((ret = o_stream_send(channel, buf, sizeof(buf))) > 0) {
		sent_bytes += ret;
		ret2 = o_stream_send(channel2, buf, sizeof(buf));
		if (ret2 <= 0)
			break;
		sent2_bytes += ret2;
	}
	test_assert(o_stream_finish(channel) == 0);
	test_assert(o_stream_finish(channel2) == 0);
	o_stream_uncork(channel);
	o_stream_uncork(channel2);
	/* We expect the first channel to have data buffered */
	test_assert(o_stream_get_buffer_used_size(channel) >=
		    o_stream_get_buffer_used_size(file_output));
	test_assert(o_stream_get_buffer_used_size(channel) -
		    o_stream_get_buffer_used_size(file_output) > 0);

	/* read everything that was already sent */
	struct istream *file_input = i_stream_create_fd(fd[0], 1024);
	struct istream *input = i_stream_create_multiplex(file_input, 4096);
	struct istream *input2 = i_stream_multiplex_add_channel(input, 1);

	struct test_hang_context ctx = {
		.input1 = input,
		.input2 = input2,
		.sent_bytes = sent_bytes,
		.sent2_bytes = sent2_bytes,
	};

	struct timeout *to = timeout_add(5000, io_loop_stop, current_ioloop);
	struct io *io = io_add_istream(file_input, test_hang_input, &ctx);
	io_loop_run(ioloop);
	io_remove(&io);
	timeout_remove(&to);

	/* everything that was sent should have been received now.
	   ostream-multiplex's internal buffer is also supposed to have
	   been sent. */
	test_assert(input->v_offset == sent_bytes);
	test_assert(input2->v_offset == sent2_bytes);
	test_assert(o_stream_get_buffer_used_size(channel) == 0);
	test_assert(o_stream_get_buffer_used_size(channel2) == 0);

	i_stream_unref(&file_input);
	i_stream_unref(&input);
	i_stream_unref(&input2);
	o_stream_unref(&channel);
	o_stream_unref(&channel2);
	o_stream_unref(&file_output);
	io_loop_destroy(&ioloop);
	test_end();
}

#define FLUSH_CALLBACK_TOTAL_BYTES 10240

struct test_flush_context {
	struct ostream *output1, *output2;
	struct istream *input1, *input2;
};

static int flush_callback1(struct test_flush_context *ctx)
{
	char buf[32];

	i_assert(ctx->output1->offset <= FLUSH_CALLBACK_TOTAL_BYTES);
	size_t bytes_left = FLUSH_CALLBACK_TOTAL_BYTES - ctx->output1->offset;

	memset(buf, '1', sizeof(buf));
	if (o_stream_send(ctx->output1, buf, I_MIN(sizeof(buf), bytes_left)) < 0)
		return -1;
	return ctx->output1->offset < FLUSH_CALLBACK_TOTAL_BYTES ? 0 : 1;
}

static int flush_callback2(struct test_flush_context *ctx)
{
	char buf[64];

	i_assert(ctx->output2->offset <= FLUSH_CALLBACK_TOTAL_BYTES);
	size_t bytes_left = FLUSH_CALLBACK_TOTAL_BYTES - ctx->output2->offset;

	memset(buf, '2', sizeof(buf));
	if (o_stream_send(ctx->output2, buf, I_MIN(sizeof(buf), bytes_left)) < 0)
		return -1;
	return ctx->output2->offset < FLUSH_CALLBACK_TOTAL_BYTES ? 0 : 1;
}

static void test_flush_input(struct test_flush_context *ctx)
{
	ssize_t ret, ret2;

	do {
		ret = i_stream_read(ctx->input1);
		if (ret > 0)
			i_stream_skip(ctx->input1, ret);
		ret2 = i_stream_read(ctx->input2);
		if (ret2 > 0)
			i_stream_skip(ctx->input2, ret2);
	} while (ret > 0 || ret2 > 0);

	test_assert(ret == 0 && ret2 == 0);
	if (ctx->input1->v_offset == FLUSH_CALLBACK_TOTAL_BYTES &&
	    ctx->input2->v_offset == FLUSH_CALLBACK_TOTAL_BYTES)
		io_loop_stop(current_ioloop);
}

static void test_ostream_multiplex_flush_callback(void)
{
	int fd[2];

	test_begin("ostream multiplex flush callback");
	if (pipe(fd) < 0)
		i_fatal("pipe() failed: %m");
	fd_set_nonblock(fd[0], TRUE);
	fd_set_nonblock(fd[1], TRUE);

	struct ioloop *ioloop = io_loop_create();
	struct ostream *file_output = o_stream_create_fd(fd[1], 1024);
	o_stream_set_no_error_handling(file_output, TRUE);
	struct ostream *channel = o_stream_create_multiplex(file_output, 4096);
	struct ostream *channel2 = o_stream_multiplex_add_channel(channel, 1);

	struct istream *file_input = i_stream_create_fd(fd[0], 1024);
	struct istream *input = i_stream_create_multiplex(file_input, 4096);
	struct istream *input2 = i_stream_multiplex_add_channel(input, 1);

	struct test_flush_context ctx = {
		.output1 = channel,
		.output2 = channel2,
		.input1 = input,
		.input2 = input2,
	};
	o_stream_set_flush_callback(channel, flush_callback1, &ctx);
	o_stream_set_flush_callback(channel2, flush_callback2, &ctx);
	o_stream_set_flush_pending(channel, TRUE);
	o_stream_set_flush_pending(channel2, TRUE);

	struct timeout *to = timeout_add(5000, io_loop_stop, current_ioloop);
	struct io *io = io_add_istream(file_input, test_flush_input, &ctx);
	io_loop_run(ioloop);
	io_remove(&io);
	timeout_remove(&to);

	test_assert(channel->offset == FLUSH_CALLBACK_TOTAL_BYTES);
	test_assert(channel2->offset == FLUSH_CALLBACK_TOTAL_BYTES);
	test_assert(input->v_offset == FLUSH_CALLBACK_TOTAL_BYTES);
	test_assert(input2->v_offset == FLUSH_CALLBACK_TOTAL_BYTES);

	test_assert(o_stream_finish(channel) == 1);
	test_assert(o_stream_finish(channel2) == 1);

	i_stream_unref(&file_input);
	i_stream_unref(&input);
	i_stream_unref(&input2);
	o_stream_unref(&channel);
	o_stream_unref(&channel2);
	o_stream_unref(&file_output);
	io_loop_destroy(&ioloop);
	test_end();
}

void test_ostream_multiplex(void)
{
	test_ostream_multiplex_simple();
	test_ostream_multiplex_stream();
	test_ostream_multiplex_cork();
	test_ostream_multiplex_hang();
	test_ostream_multiplex_flush_callback();
}
