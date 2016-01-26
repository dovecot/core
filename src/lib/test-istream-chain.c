/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

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

	input = i_stream_create_chain(&chain);
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

	test_assert(i_stream_is_eof(test_input));
	test_assert(i_stream_is_eof(test_input2));

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

	input = i_stream_create_chain(&chain);
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

void test_istream_chain(void)
{
	test_istream_chain_basic();
	test_istream_chain_early_end();
}
