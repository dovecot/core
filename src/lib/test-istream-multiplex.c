/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "str.h"
#include "crc32.h"
#include "randgen.h"
#include "istream-private.h"
#include "istream-multiplex.h"
#include "ostream.h"
#include <unistd.h>

static void test_istream_multiplex_simple(void)
{
	test_begin("istream multiplex (simple)");

	static const char data[] = "\x00\x00\x00\x00\x06Hello\x00"
				   "\x01\x00\x00\x00\x03Wor"
				   "\x00\x00\x00\x00\x00"
				   "\x01\x00\x00\x00\x03ld\x00";
	static const size_t data_len = sizeof(data)-1;
	struct istream *input = test_istream_create_data(data, data_len);
	size_t siz;

	struct istream *chan0 = i_stream_create_multiplex(input, (size_t)-1);
	struct istream *chan1 = i_stream_multiplex_add_channel(chan0, 1);

	/* nothing to read until the first byte */
	for (size_t i = 0; i <= 1+4; i++) {
		test_istream_set_size(input, i);
		test_assert(i_stream_read(chan0) == 0);
		test_assert(i_stream_read(chan1) == 0);
	}

	/* partial read of the first packet */
	size_t input_max = 1+4+3;
	test_istream_set_size(input, input_max);
	test_assert(i_stream_read(chan0) == 3);
	test_assert(memcmp(i_stream_get_data(chan0, &siz), "Hel", 3) == 0 &&
		    siz == 3);
	test_assert(i_stream_read(chan1) == 0);

	/* read the rest of the first packet and the second packet.
	   read chan1 before chan0 to see that it works. */
	input_max += 3 + 1+4+3;
	test_istream_set_size(input, input_max);
	test_assert(i_stream_read(chan1) == 3);
	test_assert(i_stream_read(chan0) == 3);
	test_assert(memcmp(i_stream_get_data(chan0, &siz), "Hello\0", 6) == 0 &&
		    siz == 6);
	test_assert(memcmp(i_stream_get_data(chan1, &siz), "Wor", 3) == 0 &&
		    siz == 3);

	/* 0-sized packet is ignored */
	input_max += 1+4;
	test_istream_set_size(input, input_max);
	test_assert(i_stream_read(chan0) == 0);
	test_assert(i_stream_read(chan1) == 0);

	/* read the final packet */
	input_max += 1+4+3;
	i_assert(input_max == data_len);
        test_istream_set_size(input, input_max);
	test_assert(i_stream_read(chan0) == 0);
	test_assert(i_stream_read(chan1) == 3);

	/* we should have the final data in all channels now */
	test_assert(memcmp(i_stream_get_data(chan0, &siz), "Hello\0", 6) == 0 &&
		    siz == 6);
	test_assert(memcmp(i_stream_get_data(chan1, &siz), "World\0", 6) == 0 &&
		    siz == 6);

	/* all channels should return EOF */
	test_assert(i_stream_read(chan0) == -1 && chan0->stream_errno == 0);
	i_stream_unref(&chan0);

	test_assert(i_stream_read(chan1) == -1 && chan1->stream_errno == 0);
	i_stream_unref(&chan1);

	i_stream_unref(&input);

	test_end();
}

static void test_istream_multiplex_maxbuf(void)
{
	test_begin("istream multiplex (maxbuf)");

	static const char data[] = "\x00\x00\x00\x00\x06Hello\x00"
				   "\x01\x00\x00\x00\x06World\x00";
	static const size_t data_len = sizeof(data)-1;
	struct istream *input = test_istream_create_data(data, data_len);
	size_t siz;

	struct istream *chan0 = i_stream_create_multiplex(input, 5);
	struct istream *chan1 = i_stream_multiplex_add_channel(chan0, 1);

	/* we get data for channel 0 and congest */
	test_assert(i_stream_read(chan1) == 0);
	/* we read data for channel 0 */
	test_assert(i_stream_read(chan0) == 5);
	/* and now it's congested */
	test_assert(i_stream_read(chan0) == -2);
	test_assert(memcmp(i_stream_get_data(chan0, &siz), "Hello", 5) == 0 &&
		    siz == 5);
	/* consume data */
	i_stream_skip(chan0, 5);
	/* we read data for channel 1 */
	test_assert(i_stream_read(chan1) == 5);
	test_assert(memcmp(i_stream_get_data(chan1, &siz), "World", 5) == 0 &&
		    siz == 5);
	/* consume data */
	i_stream_skip(chan1, 5);
	/* read last byte */
	test_assert(i_stream_read(chan0) == 1);
	/* now we get byte for channel 1 */
	test_assert(i_stream_read(chan0) == 0);
	/* now we read byte for channel 1 */
	test_assert(i_stream_read(chan1) == 1);
	/* and everything should return EOF now */
	test_assert(i_stream_read(chan1) == -1);
	test_assert(i_stream_read(chan0) == -1);

	i_stream_unref(&chan0);
	i_stream_unref(&chan1);

	i_stream_unref(&input);

	test_end();
}

static void test_istream_multiplex_random(void)
{
	const unsigned int max_channel = 6;
	const unsigned int packets_count = 30;

	test_begin("istream multiplex (random)");

	unsigned int i;
	uoff_t bytes_written = 0, bytes_read = 0;
	buffer_t *buf = buffer_create_dynamic(default_pool, 10240);
	uint32_t input_crc[max_channel];
	uint32_t output_crc[max_channel];
	memset(input_crc, 0, sizeof(input_crc));
	memset(output_crc, 0, sizeof(output_crc));

	for (i = 0; i < packets_count; i++) {
		unsigned int len = i_rand_limit(1024+1);
		unsigned char packet_data[len];
		uint32_t len_be = cpu32_to_be(len);
		unsigned int channel = i_rand_limit(max_channel);

		random_fill(packet_data, len);
		input_crc[channel] =
			crc32_data_more(input_crc[channel], packet_data, len);

		buffer_append_c(buf, channel);
		buffer_append(buf, &len_be, sizeof(len_be));
		buffer_append(buf, packet_data, len);
		bytes_written += len;
	}

	struct istream *input = test_istream_create_data(buf->data, buf->used);
	struct istream *chan[max_channel];
	chan[0] = i_stream_create_multiplex(input, 1024/4);
	for (i = 1; i < max_channel; i++)
		chan[i] = i_stream_multiplex_add_channel(chan[0], i);

	test_istream_set_size(input, 0);

	/* read from each stream, 1 byte at a time */
	size_t input_size = 0;
	int max_ret = -3;
	unsigned int read_max_channel = max_channel/2;
	bool something_read = FALSE;
	for (i = 0;;) {
		ssize_t ret = i_stream_read(chan[i]);
		if (max_ret < ret)
			max_ret = ret;
		if (ret > 0) {
			size_t size;
			const unsigned char *data =
				i_stream_get_data(chan[i], &size);

			output_crc[i] = crc32_data_more(output_crc[i], data, size);
			bytes_read += size;

			test_assert((size_t)ret == size);
			i_stream_skip(chan[i], size);
			something_read = TRUE;
		}
		if (++i < read_max_channel)
			;
		else if (max_ret == 0 && !something_read &&
			 read_max_channel < max_channel) {
			read_max_channel++;
		} else {
			if (max_ret <= -1) {
				test_assert(max_ret == -1);
				break;
			}
			if (max_ret == 0)
				test_istream_set_size(input, ++input_size);
			i = 0;
			max_ret = -3;
			something_read = FALSE;
			read_max_channel = max_channel/2;
		}
	}
	test_assert(bytes_read == bytes_written);
	for (i = 0; i < max_channel; i++) {
		test_assert_idx(input_crc[i] == output_crc[i], i);
		test_assert_idx(i_stream_read(chan[i]) == -1 &&
				chan[i]->stream_errno == 0, i);
		i_stream_unref(&chan[i]);
	}
	i_stream_unref(&input);
	buffer_free(&buf);
	test_end();
}

static unsigned int channel_counter[2] = {0, 0};

static const char *msgs[] = {
	"",
	"a",
	"bb",
	"ccc",
	"dddd",
	"eeeee",
	"ffffff"
};

static void test_istream_multiplex_stream_read(struct istream *channel)
{
	uint8_t cid = i_stream_multiplex_get_channel_id(channel);
	const char *line;
	size_t siz;

	if (i_stream_read(channel) < 0)
		return;

	while((line = i_stream_next_line(channel)) != NULL) {
		siz = strlen(line);
		test_assert_idx(siz > 0 && siz < N_ELEMENTS(msgs),
				channel_counter[cid]);
		if (siz > 0 && siz < N_ELEMENTS(msgs)) {
			test_assert_idx(strcmp(line, msgs[siz]) == 0,
					channel_counter[cid]);
		}
		channel_counter[cid]++;
	}

	if (channel_counter[0] > 100 && channel_counter[1] > 100)
		io_loop_stop(current_ioloop);
}

static void test_send_msg(struct ostream *os, uint8_t cid, const char *msg)
{
	uint32_t len = cpu32_to_be(strlen(msg) + 1);
	const struct const_iovec iov[] = {
		{ &cid, sizeof(cid) },
		{ &len, sizeof(len) },
		{ msg, strlen(msg) },
		{ "\n", 1 } /* newline added for i_stream_next_line */
	};
	o_stream_nsendv(os, iov, N_ELEMENTS(iov));
}

static void test_istream_multiplex_stream_write(struct ostream *channel)
{
	size_t rounds = i_rand() % 10;
	for(size_t i = 0; i < rounds; i++) {
		uint8_t cid = i_rand() % 2;
		test_send_msg(channel, cid, msgs[1 + i_rand() % (N_ELEMENTS(msgs) - 1)]);
	}
}

static void test_istream_multiplex_stream(void)
{
	test_begin("istream multiplex (stream)");
	struct ioloop *ioloop = io_loop_create();
	io_loop_set_current(ioloop);

	int fds[2];
	test_assert(pipe(fds) == 0);
	fd_set_nonblock(fds[0], TRUE);
	fd_set_nonblock(fds[1], TRUE);
	struct ostream *os = o_stream_create_fd(fds[1], (size_t)-1);
	struct istream *is = i_stream_create_fd(fds[0], 10 + i_rand() % 10);

	struct istream *chan0 = i_stream_create_multiplex(is, (size_t)-1);
	struct istream *chan1 = i_stream_multiplex_add_channel(chan0, 1);

	struct io *io0 =
		io_add_istream(chan0, test_istream_multiplex_stream_read, chan0);
	struct io *io1 =
		io_add_istream(chan1, test_istream_multiplex_stream_read, chan1);
	struct io *io2 =
		io_add(fds[1], IO_WRITE, test_istream_multiplex_stream_write, os);

	io_loop_run(current_ioloop);

	io_remove(&io0);
	io_remove(&io1);
	io_remove(&io2);

	i_stream_unref(&chan1);
	i_stream_unref(&chan0);
	i_stream_unref(&is);

	test_assert(o_stream_nfinish(os) == 0);
	o_stream_unref(&os);

	io_loop_destroy(&ioloop);

	i_close_fd(&fds[0]);
	i_close_fd(&fds[1]);

	test_end();
}

static void test_istream_multiplex_close_channel(void)
{
	test_begin("istream multiplex (close channel)");
	static const char *data = "\x00\x00\x00\x00\x06Hello\x00"
				  "\x01\x00\x00\x00\x06World\x00";
	static const size_t data_len = 22;
	struct istream *input = test_istream_create_data(data, data_len);
	size_t siz;

	struct istream *chan0 = i_stream_create_multiplex(input, (size_t)-1);
	struct istream *chan1 = i_stream_multiplex_add_channel(chan0, 1);

	i_stream_unref(&chan1);

	test_assert(i_stream_read(chan0) == 6);

	test_assert(memcmp(i_stream_get_data(chan0, &siz), "Hello\0", 6) == 0 &&
		    siz == 6);

	i_stream_unref(&chan0);
	i_stream_unref(&input);

	input = test_istream_create_data(data, data_len);
	chan0 = i_stream_create_multiplex(input, (size_t)-1);
	chan1 = i_stream_multiplex_add_channel(chan0, 1);

	/* this is needed to populate chan1 data */
	(void)i_stream_read(chan0);
	i_stream_unref(&chan0);

	test_assert(i_stream_read(chan1) == 6);

	test_assert(memcmp(i_stream_get_data(chan1, &siz), "World\0", 6) == 0 &&
		    siz == 6);

	i_stream_unref(&chan1);
	i_stream_unref(&input);

	test_end();
}

void test_istream_multiplex(void)
{
	test_istream_multiplex_simple();
	test_istream_multiplex_maxbuf();
	test_istream_multiplex_random();
	test_istream_multiplex_stream();
	test_istream_multiplex_close_channel();
}
