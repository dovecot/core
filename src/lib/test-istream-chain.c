/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream-private.h"
#include "istream-chain.h"

static void test_istream_chain_basic(void)
{
	struct istream *input, *test_input, *test_input2;
	struct istream_chain *chain;
	const unsigned char *data;
	size_t size;

	test_begin("istream chain");

	test_input = test_istream_create("stream1");
	test_input2 = test_istream_create("STREAM2");

	input = i_stream_create_chain(&chain, IO_BLOCK_SIZE);
	/* no input */
	test_assert(i_stream_read(input) == 0);
	/* stream1 input */
	i_stream_chain_append(chain, test_input);
	test_assert(i_stream_read(input) == 7);
	data = i_stream_get_data(input, &size);
	test_assert(size == 7 && memcmp(data, "stream1", 7) == 0);
	test_assert(i_stream_read(input) == 0);
	data = i_stream_get_data(input, &size);
	test_assert(size == 7 && memcmp(data, "stream1", 7) == 0);
	/* STREAM2 input */
	i_stream_chain_append(chain, test_input2);
	test_assert(i_stream_read(input) == 7);
	data = i_stream_get_data(input, &size);
	test_assert(size == 14 && memcmp(data, "stream1STREAM2", 14) == 0);
	test_assert(i_stream_read(input) == 0);
	data = i_stream_get_data(input, &size);
	test_assert(size == 14 && memcmp(data, "stream1STREAM2", 14) == 0);
	/* EOF */
	i_stream_chain_append_eof(chain);
	test_assert(i_stream_read(input) == -1 &&
		    input->eof && input->stream_errno == 0);
	data = i_stream_get_data(input, &size);
	test_assert(size == 14 && memcmp(data, "stream1STREAM2", 14) == 0);

	i_stream_unref(&input);

	test_assert(test_input->eof && test_input->stream_errno == 0);
	test_assert(test_input2->eof && test_input2->stream_errno == 0);

	i_stream_unref(&test_input);
	i_stream_unref(&test_input2);
	test_end();
}

static void test_istream_chain_early_end(void)
{
	struct istream *input, *test_input;
	struct istream_chain *chain;

	test_begin("istream chain early end");

	test_input = test_istream_create("string");
	test_istream_set_size(test_input, 3);
	test_istream_set_allow_eof(test_input, FALSE);

	input = i_stream_create_chain(&chain, IO_BLOCK_SIZE);
	i_stream_chain_append(chain, test_input);
	test_assert(i_stream_read(input) == 3);
	test_istream_set_size(test_input, 5);
	test_assert(i_stream_read(input) == 2);
	/* with current implementation we could skip less than 5 and have
	   v_offset<5, but I don't think that can work in all situations.
	   the normal case is anyway that we'll read everything up until some
	   point and skip over all the data up to there. */
	i_stream_skip(input, 5);
	i_stream_unref(&input);

	test_assert(test_input->v_offset == 5);
	i_stream_unref(&test_input);
	test_end();
}

static void test_istream_chain_accumulate(void)
{
	struct istream *input, *tmp_istream;
	struct istream *test_istreams[5];
	struct istream_chain *chain;
	const unsigned char *data;
	size_t size;

	test_begin("istream chain accumulate");

	test_istreams[0] = test_istream_create("abcdefghijklmnopqrst");
	test_istreams[1] = test_istream_create("ABCDEFGHIJKLMNOPQRSTUVWXY");
	test_istreams[2] = test_istream_create("!\"#$%&'()*+,-./01234567890:;<=");
	test_istreams[3] = test_istream_create("z1y2x3w4v5u6t7s8r9q0p.o,n");
	test_istreams[4] = test_istream_create("aAbBcCdDeEfFgGhHiIjJ");

	input = i_stream_create_chain(&chain, IO_BLOCK_SIZE);
	/* no input */
	test_assert(i_stream_read(input) == 0);

	/* first stream */
	i_stream_chain_append(chain, test_istreams[0]);
	tmp_istream = test_istreams[0]; i_stream_unref(&tmp_istream);
	test_assert(i_stream_read_data(input, &data, &size, 0) == 1);
	test_assert(size == 20);
	test_assert(memcmp(data, "abcdefghijklmnopqrst", 20) == 0);

	/* partially skip */
	i_stream_skip(input, 12);

	/* second stream */
	i_stream_chain_append(chain, test_istreams[1]);
	tmp_istream = test_istreams[1]; i_stream_unref(&tmp_istream);
	test_istream_set_size(test_istreams[1], 0);
	test_assert(i_stream_read_data(input, &data, &size, 10) == 0);
	test_assert(size == 8);
	test_istream_set_size(test_istreams[1], 10);
	test_assert(i_stream_read_data(input, &data, &size, 10) == 1);
	test_assert(size == 18);
	test_istream_set_allow_eof(test_istreams[1], FALSE);
	test_assert(i_stream_read(input) == 0);
	test_istream_set_size(test_istreams[1], 25);
	test_istream_set_allow_eof(test_istreams[1], TRUE);
	test_assert(i_stream_read_data(input, &data, &size, 30) == 1);
	test_assert(size == 33);
	test_assert(memcmp(data, "mnopqrst"
		"ABCDEFGHIJKLMNOPQRSTUVWXY", 33) == 0);

	/* partially skip */
	i_stream_skip(input, 12);

	/* third stream */
	i_stream_chain_append(chain, test_istreams[2]);
	tmp_istream = test_istreams[2]; i_stream_unref(&tmp_istream);
	test_istream_set_size(test_istreams[2], 0);
	test_assert(i_stream_read(input) == 0);
	test_istream_set_size(test_istreams[2], 30);
	test_assert(i_stream_read_data(input, &data, &size, 25) == 1);
	test_assert(size == 51);
	test_assert(memcmp(data, "EFGHIJKLMNOPQRSTUVWXY"
		"!\"#$%&'()*+,-./01234567890:;<=", 51) == 0);
	test_assert(i_stream_read(input) == 0);

	/* partially skip */
	i_stream_skip(input, 12);

	/* forth stream */
	i_stream_chain_append(chain, test_istreams[3]);
	tmp_istream = test_istreams[3]; i_stream_unref(&tmp_istream);
	test_assert(i_stream_read_data(input, &data, &size, 40) == 1);
	test_assert(size == 64);
	test_assert(memcmp(data, "QRSTUVWXY"
		"!\"#$%&'()*+,-./01234567890:;<="
		"z1y2x3w4v5u6t7s8r9q0p.o,n", 64) == 0);

	/* partially skip */
	i_stream_skip(input, 6);

	/* fifth stream */
	i_stream_chain_append(chain, test_istreams[4]);
	tmp_istream = test_istreams[4]; i_stream_unref(&tmp_istream);
	test_assert(i_stream_read_data(input, &data, &size, 60) == 1);
	test_assert(size == 78);
	test_assert(memcmp(data, "WXY"
		"!\"#$%&'()*+,-./01234567890:;<="
		"z1y2x3w4v5u6t7s8r9q0p.o,n"
		"aAbBcCdDeEfFgGhHiIjJ", 78) == 0);

	/* EOF */
	i_stream_chain_append_eof(chain);
	test_assert(i_stream_read(input) == -1);
	test_assert(input->eof && input->stream_errno == 0);
	test_assert(i_stream_read_data(input, &data, &size, 78) == -1);
	test_assert(size == 78);
	test_assert(memcmp(data, "WXY"
		"!\"#$%&'()*+,-./01234567890:;<="
		"z1y2x3w4v5u6t7s8r9q0p.o,n"
		"aAbBcCdDeEfFgGhHiIjJ", 78) == 0);

	/* skip rest */
	i_stream_skip(input, 78);

	test_assert(i_stream_read(input) == -1);
	test_assert(input->eof && input->stream_errno == 0);
	data = i_stream_get_data(input, &size);
	test_assert(size == 0);

	i_stream_unref(&input);
	test_end();
}

void test_istream_chain(void)
{
	test_istream_chain_basic();
	test_istream_chain_early_end();
	test_istream_chain_accumulate();
}
