/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "str.h"
#include "istream.h"
#include "ostream-private.h"
#include "istream-multiplex.h"
#include "ostream-multiplex.h"
#include "iostream-multiplex-private.h"
#include "ostream.h"
#include <unistd.h>

#include "hex-binary.h"

static void test_ostream_multiplex_packet_simple(void)
{
	test_begin("ostream multiplex packet (simple)");

	const unsigned char expected[] = {
		'\x00','\x00','\x00','\x00','\x05','\x68','\x65',
		'\x6c','\x6c','\x6f','\x01','\x00','\x00','\x00',
		'\x05','\x77','\x6f','\x72','\x6c','\x64'
	};

	buffer_t *result = t_str_new(64);
	struct ostream *os = test_ostream_create(result);
	struct ostream *os2 = o_stream_create_multiplex(os, SIZE_MAX,
		OSTREAM_MULTIPLEX_FORMAT_PACKET);
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
	size_t rounds = 1 + i_rand_limit(10);
	for(size_t i = 0; i < rounds; i++) {
		if ((i_rand_limit(2)) != 0) {
			o_stream_cork(chan1);
			/* send one byte at a time */
			for(const char *p = msgs[i_rand_limit(N_ELEMENTS(msgs))];
			    *p != '\0'; p++) {
				o_stream_nsend(chan1, p, 1);
			}
			o_stream_uncork(chan1);
		} else {
			o_stream_nsend_str(chan0,
					   msgs[i_rand_limit(N_ELEMENTS(msgs))]);
		}
	}
}

static void test_ostream_multiplex_packet_stream(void)
{
	test_begin("ostream multiplex packet (stream)");

	struct ioloop *ioloop = io_loop_create();
	io_loop_set_current(ioloop);

	int fds[2];
	test_assert(pipe(fds) == 0);
	fd_set_nonblock(fds[0], TRUE);
	fd_set_nonblock(fds[1], TRUE);
	struct ostream *os = o_stream_create_fd(fds[1], SIZE_MAX);
	struct istream *is = i_stream_create_fd(fds[0], SIZE_MAX);

	chan0 = o_stream_create_multiplex(os, SIZE_MAX,
					  OSTREAM_MULTIPLEX_FORMAT_PACKET);
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

static void test_ostream_multiplex_packet_cork(void)
{
	test_begin("ostream multiplex packet (corking)");
	buffer_t *output = t_buffer_create(128);
	struct ostream *os = test_ostream_create(output);
	struct ostream *chan0 = o_stream_create_multiplex(os, SIZE_MAX,
		OSTREAM_MULTIPLEX_FORMAT_PACKET);

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

static void test_ostream_multiplex_packet_cork_transfer(void)
{
	test_begin("ostream multiplex packet (cork transfer)");
	buffer_t *output = t_buffer_create(128);
	struct ostream *os = test_ostream_create(output);
	o_stream_set_no_error_handling(os, TRUE);

	/* Parent corked before wrapping. The multiplex must transfer
	   the cork onto channel 0 instead of asserting. */
	o_stream_cork(os);
	test_assert(o_stream_is_corked(os));

	struct ostream *chan0 = o_stream_create_multiplex(os, SIZE_MAX,
		OSTREAM_MULTIPLEX_FORMAT_PACKET);
	test_assert(!o_stream_is_corked(os));
	test_assert(o_stream_is_corked(chan0));

	/* Cork on channel 0 buffers the write. */
	test_assert(o_stream_send_str(chan0, "hi") == 2);
	test_assert(output->used == 0);

	o_stream_uncork(chan0);
	test_assert(o_stream_flush(os) == 1);
	test_assert(output->used == 7);
	test_assert(memcmp(output->data, "\0\0\0\0\2hi", 7) == 0);

	/* Re-cork channel 0, then destroy the multiplex: cork must
	   transfer back to the parent. */
	o_stream_cork(chan0);
	test_assert(!o_stream_is_corked(os));
	o_stream_unref(&chan0);
	test_assert(o_stream_is_corked(os));

	o_stream_uncork(os);
	o_stream_unref(&os);

	test_end();
}

static void test_ostream_multiplex_packet_cork_transfer_buffered_parent(void)
{
	test_begin("ostream multiplex packet (cork transfer buffered parent)");
	struct ioloop *ioloop = io_loop_create();
	buffer_t *output = t_buffer_create(128);
	struct ostream *os = test_ostream_create_nonblocking(output, 128);
	o_stream_set_no_error_handling(os, TRUE);

	/* Buffer data in the parent while corked. Wrapping must transfer
	   the cork state without flushing this data early. */
	o_stream_cork(os);
	test_ostream_set_max_output_size(os, 0);
	test_assert(o_stream_send_str(os, "pre") == 3);
	test_assert(output->used == 0);

	test_ostream_set_max_output_size(os, SIZE_MAX);
	struct ostream *chan0 = o_stream_create_multiplex(os, SIZE_MAX,
		OSTREAM_MULTIPLEX_FORMAT_PACKET);
	test_assert(output->used == 0);
	test_assert(!o_stream_is_corked(os));
	test_assert(o_stream_is_corked(chan0));

	test_assert(o_stream_send_str(chan0, "hi") == 2);
	test_assert(output->used == 0);

	o_stream_uncork(chan0);
	test_assert(o_stream_flush(os) == 1);
	test_assert(output->used == 10);
	test_assert(memcmp(output->data, "pre\0\0\0\0\2hi", 10) == 0);

	o_stream_unref(&chan0);
	o_stream_unref(&os);
	io_loop_destroy(&ioloop);

	test_end();
}

static void test_ostream_multiplex_stream_corked_failed_parent(void)
{
	int fds[2];

	test_begin("ostream multiplex stream (corked channel, failed parent)");
	lib_signals_ignore(SIGPIPE, TRUE);
	if (pipe(fds) < 0)
		i_panic("pipe() failed: %m");
	/* no reader - writes to the parent fail with EPIPE */
	i_close_fd(&fds[0]);

	struct ostream *os = o_stream_create_fd(fds[1], 1024);
	o_stream_set_no_error_handling(os, TRUE);
	struct ostream *chan0 = o_stream_create_multiplex(os, SIZE_MAX,
		OSTREAM_MULTIPLEX_FORMAT_STREAM_CONTINUE);

	/* Send more than the parent's buffer size through the corked
	   channel 0: the multiplex corks the parent and writes to it,
	   which fails with EPIPE. The multiplex's uncork afterwards is
	   a no-op on the failed parent, so the parent stays corked. */
	o_stream_cork(chan0);
	char buf[4096];
	memset(buf, 'a', sizeof(buf));
	test_assert(o_stream_send(chan0, buf, sizeof(buf)) < 0);
	test_assert(chan0->stream_errno == EPIPE);
	test_assert(o_stream_is_corked(os));

	/* Destroying the still-corked channel 0 must not attempt to
	   transfer the cork back to the failed parent. */
	o_stream_unref(&chan0);
	test_assert(os->stream_errno == EPIPE);
	o_stream_unref(&os);
	i_close_fd(&fds[1]);

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

static void test_ostream_multiplex_packet_hang(void)
{
	int fd[2];

	test_begin("ostream multiplex packet (hang)");
	if (pipe(fd) < 0)
		i_fatal("pipe() failed: %m");
	fd_set_nonblock(fd[0], TRUE);
	fd_set_nonblock(fd[1], TRUE);

	struct ioloop *ioloop = io_loop_create();
	struct ostream *file_output = o_stream_create_fd(fd[1], 1024);
	o_stream_set_no_error_handling(file_output, TRUE);
	struct ostream *channel = o_stream_create_multiplex(file_output, 4096,
		OSTREAM_MULTIPLEX_FORMAT_PACKET);
	struct ostream *channel2 = o_stream_multiplex_add_channel(channel, 1);
	char buf[257];

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
	/* The previous writes must leave some data buffered into channel 0.
	   Otherwise the test isn't fully testing what it's supposed to be. */
	test_assert(o_stream_get_buffer_used_size(channel) >
		    o_stream_get_buffer_used_size(file_output));

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

static void test_ostream_multiplex_packet_flush_callback(void)
{
	int fd[2];

	test_begin("ostream multiplex packet (flush callback)");
	if (pipe(fd) < 0)
		i_fatal("pipe() failed: %m");
	fd_set_nonblock(fd[0], TRUE);
	fd_set_nonblock(fd[1], TRUE);

	struct ioloop *ioloop = io_loop_create();
	struct ostream *file_output = o_stream_create_fd(fd[1], 1024);
	o_stream_set_no_error_handling(file_output, TRUE);
	struct ostream *channel = o_stream_create_multiplex(file_output, 4096,
		OSTREAM_MULTIPLEX_FORMAT_PACKET);
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

static bool buf_expect(buffer_t *buf, const void *data, size_t size)
{
	if (buf->used < size || memcmp(buf->data, data, size) != 0)
		return FALSE;
	buffer_delete(buf, 0, size);
	return TRUE;
}

static void test_ostream_multiplex_stream(void)
{
	static unsigned char multiplex_header[] = "\xFF\xFF\xFF\xFF\xFF\x00\x02";
	char c;

	test_begin("ostream multiplex stream");
	buffer_t *buf = buffer_create_dynamic(default_pool, 1024);
	struct ostream *output_buf = o_stream_create_buffer(buf);
	struct ostream *output =
		o_stream_create_multiplex(output_buf, SIZE_MAX,
					  OSTREAM_MULTIPLEX_FORMAT_STREAM);
	test_assert(buf->used == 0);

	o_stream_nsend(output, "x", 1);
	/* starts with header */
	buf_expect(buf, multiplex_header, sizeof(multiplex_header)-1);
	buf_expect(buf, IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX,
		   IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX_LEN);
	/* initial channel switch to 0 */
	c = MULTIPLEX_ISTREAM_SWITCH_TYPE_CHANNEL_ID;
	buf_expect(buf, &c, 1);
	c = 0;
	buf_expect(buf, &c, 1);
	/* the actual data we sent */
	c = 'x';
	buf_expect(buf, &c, 1);
	test_assert(buf->used == 0);

	/* same channel, so continues with sent data */
	o_stream_nsend(output, "y", 1);
	c = 'y';
	buf_expect(buf, &c, 1);
	test_assert(buf->used == 0);

	/* no need to escape the header if sent again */
	o_stream_nsend(output, multiplex_header, sizeof(multiplex_header)-1);
	buf_expect(buf, multiplex_header, sizeof(multiplex_header)-1);
	test_assert(buf->used == 0);

	/* channel switch is escaped */
	o_stream_nsend(output, IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX,
		       IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX_LEN);
	buf_expect(buf, "\x03\xFE\x01\xFE", 4);
	test_assert(buf->used == 0);

	/* channel switch's first character is escaped */
	o_stream_nsend(output, IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX, 1);
	buf_expect(buf, "\x03\xFE\x01", 3);
	test_assert(buf->used == 0);

	/* channel switch's first character followed by non-second character
	   is not escaped */
	char data[2] = { IOSTREAM_MULTIPLEX_CHANNEL_SWITCH_PREFIX[0], 'x' };
	o_stream_nsend(output, data, 2);
	buf_expect(buf, data, 2);
	test_assert(buf->used == 0);

	/* 2nd channel */
	struct ostream *output2 =
		o_stream_multiplex_add_channel(output, 3);
	o_stream_nsend(output2, "z", 1);
	buf_expect(buf, "\x03\xFE\x00\x03z", 5);
	test_assert(buf->used == 0);

	o_stream_nsend(output2, "abc", 3);
	buf_expect(buf, "abc", 3);
	test_assert(buf->used == 0);

	/* back to 1st channel */
	o_stream_nsend(output, "def", 3);
	buf_expect(buf, "\x03\xFE\000\000def", 7);
	test_assert(buf->used == 0);

	o_stream_nsend(output, "g", 1);
	buf_expect(buf, "g", 1);
	test_assert(buf->used == 0);

	test_assert(o_stream_flush(output) == 1);

	(void)o_stream_finish(output2);
	o_stream_unref(&output2);
	o_stream_unref(&output);
	o_stream_unref(&output_buf);
	buffer_free(&buf);
	test_end();
}

/* The 9-byte header that the STREAM format writes out before any data. */
static const unsigned char stream_header[IOSTREAM_MULTIPLEX_HEADER_SIZE] =
	"\xFF\xFF\xFF\xFF\xFF\x00\x02\x03\xFE";

/* imap-fetch sets max_buffer_size=0 on the output while it streams a body
   straight to the socket. When that output is an ostream-multiplex channel
   (login proxy), the 0 reaches the multiplex parent, whose
   o_stream_get_buffer_avail_size() then always reports 0. The STREAM format
   must still write through it - it must not be gated on the parent's avail. */
static void test_ostream_multiplex_stream_maxbuf0(void)
{
	test_begin("ostream multiplex stream (max_buffer_size=0 parent)");

	buffer_t *output = buffer_create_dynamic(default_pool, 256);
	/* max_buffer_size==0 parent, but the socket itself has room
	   (max_output_size defaults to SIZE_MAX). */
	struct ostream *parent = test_ostream_create_nonblocking(output, 0);
	o_stream_set_no_error_handling(parent, TRUE);
	test_assert(o_stream_get_buffer_avail_size(parent) == 0);

	struct ostream *chan0 = o_stream_create_multiplex(parent, SIZE_MAX,
		OSTREAM_MULTIPLEX_FORMAT_STREAM);

	/* The data has to reach the socket, not get wedged in the channel
	   buffer waiting for a parent avail that never comes. */
	test_assert(o_stream_send_str(chan0, "hello") == 5);
	test_assert(o_stream_get_buffer_used_size(chan0) == 0);
	test_assert(output->used == sizeof(stream_header) + 5);
	test_assert(memcmp(output->data, stream_header,
			   sizeof(stream_header)) == 0);
	test_assert(memcmp(CONST_PTR_OFFSET(output->data, sizeof(stream_header)),
			   "hello", 5) == 0);

	o_stream_unref(&chan0);
	o_stream_unref(&parent);
	buffer_free(&output);
	test_end();
}

/* o_stream_send_istream() of an in-memory istream returns all of its data in
   one read, so a field larger than IO_BLOCK_SIZE arrives as a single
   oversized sendv. Against a max_buffer_size==0 parent the channel grows its
   effective avail to IO_BLOCK_SIZE - it must then buffer up to that instead of
   refusing the whole send and returning 0 (which busy-looped, making no
   forward progress). */
static void test_ostream_multiplex_stream_oversized_send(void)
{
	test_begin("ostream multiplex stream (single send > IO_BLOCK_SIZE)");

	buffer_t *output = buffer_create_dynamic(default_pool, 4 * IO_BLOCK_SIZE);
	struct ostream *parent = test_ostream_create_nonblocking(output, 0);
	o_stream_set_no_error_handling(parent, TRUE);

	struct ostream *chan0 = o_stream_create_multiplex(parent, SIZE_MAX,
		OSTREAM_MULTIPLEX_FORMAT_STREAM);

	size_t payload = IO_BLOCK_SIZE + 4096;
	unsigned char *data = i_malloc(payload);
	/* 'A' never equals the 0x03 switch-prefix byte, so nothing is escaped
	   and the output is exactly header + payload. */
	memset(data, 'A', payload);

	/* A single send larger than IO_BLOCK_SIZE must make forward progress by
	   buffering up to the grown avail (IO_BLOCK_SIZE). */
	ssize_t ret = o_stream_send(chan0, data, payload);
	test_assert(ret == IO_BLOCK_SIZE);

	/* Drain the rest; every send must keep making progress. */
	size_t sent = ret > 0 ? (size_t)ret : 0;
	for (unsigned int i = 0; sent < payload && i < 100; i++) {
		ret = o_stream_send(chan0, data + sent, payload - sent);
		test_assert(ret > 0);
		if (ret <= 0)
			break;
		sent += ret;
	}
	test_assert(sent == payload);
	test_assert(o_stream_get_buffer_used_size(chan0) == 0);
	/* single channel, no escaping: output is just header + payload */
	test_assert(output->used == sizeof(stream_header) + payload);

	i_free(data);
	o_stream_unref(&chan0);
	o_stream_unref(&parent);
	buffer_free(&output);
	test_end();
}

/* Once the socket is congested the channel must apply backpressure so
   o_stream_send_istream() stops and waits (WAIT_OUTPUT), instead of buffering
   the whole body into the parent without bound and busy-looping a writev() on
   the full socket. A regression either busy-loops forever (never returns) or
   swallows the whole body (FINISHED) - the first is caught by the subprocess
   watchdog killing the hung child, the second by the assertions below failing
   in the child. Either way the parent test fails cleanly. */
static int test_stream_backpressure_child(void *context ATTR_UNUSED)
{
	struct ioloop *ioloop = io_loop_create();
	int fd[2];
	if (pipe(fd) < 0)
		i_fatal("pipe() failed: %m");
	fd_set_nonblock(fd[0], TRUE);
	fd_set_nonblock(fd[1], TRUE);

	/* Small parent buffer so avail reaches 0 quickly once the socket fills;
	   this is the congested state where the backpressure fix matters. */
	struct ostream *parent = o_stream_create_fd(fd[1], 4096);
	o_stream_set_no_error_handling(parent, TRUE);
	struct ostream *chan0 = o_stream_create_multiplex(parent, SIZE_MAX,
		OSTREAM_MULTIPLEX_FORMAT_STREAM);

	/* A body larger than the socket buffer, streamed straight from memory as
	   imap-fetch does with o_stream_send_istream(). Nobody reads fd[0]. */
	size_t body_size = 1024 * 1024;
	unsigned char *body = i_malloc(body_size);
	memset(body, 'A', body_size);
	struct istream *source = i_stream_create_from_data(body, body_size);

	enum ostream_send_istream_result res =
		o_stream_send_istream(chan0, source);
	test_assert(res == OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT);
	test_assert(source->v_offset < body_size);
	test_assert(o_stream_get_buffer_used_size(chan0) < body_size);

	/* Backpressure must be temporary: draining the reader (and flushing the
	   parent's backlog to the now-writable socket) lets the rest go through. */
	bool progressed = FALSE;
	for (unsigned int i = 0; i < 8192 && !progressed; i++) {
		char rbuf[4096];
		while (read(fd[0], rbuf, sizeof(rbuf)) > 0)
			;
		uoff_t prev_offset = source->v_offset;
		(void)o_stream_flush(chan0);
		res = o_stream_send_istream(chan0, source);
		if (res == OSTREAM_SEND_ISTREAM_RESULT_FINISHED ||
		    source->v_offset > prev_offset)
			progressed = TRUE;
	}
	test_assert(progressed);

	i_stream_unref(&source);
	i_free(body);
	o_stream_unref(&chan0);
	o_stream_unref(&parent);
	i_close_fd(&fd[0]);
	i_close_fd(&fd[1]);
	io_loop_destroy(&ioloop);
	return 0;
}

static void test_ostream_multiplex_stream_backpressure(void)
{
	test_begin("ostream multiplex stream (backpressure)");
	/* Run in a subprocess: a regression makes o_stream_send_istream() spin on
	   the full socket and never return, which would wedge the whole test
	   binary. The watchdog kills a hung child and records the failure. */
	(void)test_subprocess_fork(test_stream_backpressure_child, NULL, TRUE);
	/* A passing child exits on its own, so this timeout only bounds how long
	   a regression's runaway child is allowed to spin before it's killed. */
	test_subprocess_wait_all(30);
	test_subprocess_kill_all(5);
	test_end();
}

/* STREAM_CONTINUE is what the imap process uses to keep writing to a multiplex
   stream that imap-login already opened (and already emitted the header for).
   It writes no header of its own and starts with an explicit channel switch. */
static void test_ostream_multiplex_stream_continue(void)
{
	test_begin("ostream multiplex stream (continue)");

	buffer_t *output = buffer_create_dynamic(default_pool, 256);
	struct ostream *parent = test_ostream_create(output);

	struct ostream *chan0 = o_stream_create_multiplex(parent, SIZE_MAX,
		OSTREAM_MULTIPLEX_FORMAT_STREAM_CONTINUE);

	/* No header; first write is a channel switch to 0 followed by data. */
	test_assert(o_stream_send_str(chan0, "hello") == 5);
	test_assert(o_stream_flush(chan0) == 1);
	test_assert(output->used == 4 + 5);
	test_assert(memcmp(output->data, "\x03\xFE\x00\x00hello", 9) == 0);
	buffer_set_used_size(output, 0);

	/* Same channel continues without another switch. */
	test_assert(o_stream_send_str(chan0, "world") == 5);
	test_assert(o_stream_flush(chan0) == 1);
	test_assert(output->used == 5);
	test_assert(memcmp(output->data, "world", 5) == 0);
	buffer_set_used_size(output, 0);

	/* A second channel switches with its channel id. */
	struct ostream *chan5 = o_stream_multiplex_add_channel(chan0, 5);
	test_assert(o_stream_send_str(chan5, "z") == 1);
	test_assert(o_stream_flush(chan5) == 1);
	test_assert(output->used == 5);
	test_assert(memcmp(output->data, "\x03\xFE\x00\x05z", 5) == 0);

	o_stream_unref(&chan5);
	o_stream_unref(&chan0);
	o_stream_unref(&parent);
	buffer_free(&output);
	test_end();
}

struct fatal_multiplex_ctx {
	struct ostream *chan0;
	struct ostream *parent;
	buffer_t *output;
};
static struct fatal_multiplex_ctx fatal_ctx;

static void fatal_ostream_multiplex_free(struct fatal_multiplex_ctx *ctx)
{
	o_stream_unref(&ctx->chan0);
	o_stream_unref(&ctx->parent);
	buffer_free(&ctx->output);
}

enum fatal_test_state fatal_ostream_multiplex(unsigned int stage)
{
	switch (stage) {
	case 0:
		test_begin("fatal ostream multiplex packet (max_buffer_size=0 parent)");
		fatal_ctx.output = buffer_create_dynamic(default_pool, 64);
		fatal_ctx.parent =
			test_ostream_create_nonblocking(fatal_ctx.output, 0);
		o_stream_set_no_error_handling(fatal_ctx.parent, TRUE);
		fatal_ctx.chan0 = o_stream_create_multiplex(fatal_ctx.parent,
			SIZE_MAX, OSTREAM_MULTIPLEX_FORMAT_PACKET);
		/* A PACKET parent whose max_buffer_size can't even hold a frame
		   header can never drain enough to send a packet, so it must
		   fail loudly instead of silently hanging. */
		test_expect_fatal_string("max_buffer_size(mstream->parent) >= 6");
		test_fatal_set_callback(fatal_ostream_multiplex_free, &fatal_ctx);
		o_stream_nsend_str(fatal_ctx.chan0, "hello");
		return FATAL_TEST_FAILURE;
	default:
		test_end();
		return FATAL_TEST_FINISHED;
	}
}

void test_ostream_multiplex(void)
{
	test_ostream_multiplex_packet_simple();
	test_ostream_multiplex_packet_stream();
	test_ostream_multiplex_packet_cork();
	test_ostream_multiplex_packet_cork_transfer();
	test_ostream_multiplex_packet_cork_transfer_buffered_parent();
	test_ostream_multiplex_stream_corked_failed_parent();
	test_ostream_multiplex_packet_hang();
	test_ostream_multiplex_packet_flush_callback();
	test_ostream_multiplex_stream();
	test_ostream_multiplex_stream_maxbuf0();
	test_ostream_multiplex_stream_oversized_send();
	test_ostream_multiplex_stream_backpressure();
	test_ostream_multiplex_stream_continue();
}
