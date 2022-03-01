/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream-private.h"
#include "istream-base64.h"
#include "istream-try.h"

#define MIN_FULL_SIZE 1

static void test_istream_try_normal(void)
{
	bool finished = FALSE;

	test_begin("istream try");
	for (unsigned int test = 0; test <= 10; test++) {
		struct istream *test_inputs[3], *try_input;

		test_inputs[0] = test_istream_create("1");
		test_inputs[1] = test_istream_create("2");
		test_inputs[2] = NULL;
		test_istream_set_size(test_inputs[0], 0);
		test_istream_set_size(test_inputs[1], 0);
		try_input = istream_try_create(test_inputs, MIN_FULL_SIZE);

		/* nonblocking read */
		test_assert_idx(i_stream_read(try_input) == 0, test);

		switch (test) {
		case 0:
			/* stream 0 is available */
			test_istream_set_size(test_inputs[0], 1);
			test_assert_idx(i_stream_read(try_input) == 1, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[0]) == 1, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 0, test);
			break;
		case 1:
			/* stream 1 is available, but not used before 0 */
			test_istream_set_size(test_inputs[1], 1);
			test_assert_idx(i_stream_read(try_input) == 0, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[0]) == 0, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 0, test);
			/* continue failing stream 0 -> 1 is available */
			test_inputs[0]->stream_errno = EINVAL;
			test_assert_idx(i_stream_read(try_input) == 1, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[0]) == 0, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 1, test);
			break;
		case 2:
			/* both streams are available - stream 0 is read */
			test_istream_set_size(test_inputs[0], 1);
			test_istream_set_size(test_inputs[1], 1);
			test_assert_idx(i_stream_read(try_input) == 1, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[0]) == 1, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 0, test);
			break;
		case 3:
			/* stream 0 fails */
			test_inputs[0]->stream_errno = EINVAL;
			test_assert_idx(i_stream_read(try_input) == 0, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[0]) == 0, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 0, test);
			/* continue making stream 1 available */
			test_istream_set_size(test_inputs[1], 1);
			test_assert_idx(i_stream_read(try_input) == 1, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[0]) == 0, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 1, test);
			break;
		case 4:
			/* stream 1 fails */
			test_inputs[1]->stream_errno = EINVAL;
			test_assert_idx(i_stream_read(try_input) == 0, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[0]) == 0, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 0, test);
			break;
		case 5:
			/* stream 0 fails, stream 1 is available */
			test_inputs[0]->stream_errno = EINVAL;
			test_istream_set_size(test_inputs[1], 1);
			test_assert_idx(i_stream_read(try_input) == 1, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[0]) == 0, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 1, test);
			break;
		case 6:
			/* stream 0 is available, stream 1 fails */
			test_inputs[1]->stream_errno = EINVAL;
			test_istream_set_size(test_inputs[0], 1);
			test_assert_idx(i_stream_read(try_input) == 1, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[0]) == 1, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 0, test);
			break;
		case 7:
			/* both streams fail */
			test_inputs[0]->stream_errno = EINVAL;
			test_inputs[1]->stream_errno = EINVAL;
			test_assert_idx(i_stream_read(try_input) == -1, test);
			test_assert_idx(try_input->stream_errno == EINVAL, test);
			break;
		case 8:
			/* stream 0 fails with EINVAL, stream 1 with EIO */
			test_inputs[0]->stream_errno = EINVAL;
			test_inputs[1]->stream_errno = EIO;
			test_assert_idx(i_stream_read(try_input) == -1, test);
			test_assert_idx(try_input->stream_errno == EIO, test);
			break;
		case 9:
			/* stream 0 fails with EIO, stream 1 with EINVAL */
			test_inputs[0]->stream_errno = EIO;
			test_inputs[1]->stream_errno = EINVAL;
			test_assert_idx(i_stream_read(try_input) == -1, test);
			test_assert_idx(try_input->stream_errno == EIO, test);
			break;
		case 10:
			/* stream 0 fails with EIO, stream 1 would work.. */
			test_inputs[0]->stream_errno = EIO;
			test_istream_set_size(test_inputs[1], 1);
			test_assert_idx(i_stream_read(try_input) == -1, test);
			test_assert_idx(try_input->stream_errno == EIO, test);
			test_assert_idx(i_stream_get_data_size(test_inputs[1]) == 0, test);

			finished = TRUE;
			break;
		}

		test_assert_idx(test_inputs[0]->v_offset == 0, test);
		test_assert_idx(test_inputs[1]->v_offset == 0, test);

		i_stream_unref(&test_inputs[0]);
		i_stream_unref(&test_inputs[1]);
		i_stream_unref(&try_input);
	}
	i_assert(finished);
	test_end();
}

static void test_istream_try_empty(void)
{
	test_begin("istream try empty stream");
	struct istream *test_inputs[] = {
		test_istream_create(""),
		test_istream_create(""),
		NULL
	};
	struct istream *try_input =
		istream_try_create(test_inputs, MIN_FULL_SIZE);
	test_assert(i_stream_read(try_input) == -1);
	test_assert(try_input->eof);
	test_assert(try_input->stream_errno == 0);
	i_stream_unref(&test_inputs[0]);
	i_stream_unref(&test_inputs[1]);
	i_stream_unref(&try_input);
	test_end();
}

static void test_istream_try_buffer_full(void)
{
	const char *test_strings[] = { "Zm9v", "YmFy" };
	struct istream *test_inputs[3], *try_input, *input, *input2;

	test_begin("istream try buffer full");

	for (unsigned int i = 0; i < 2; i++) {
		input = test_istream_create(test_strings[i]);
		test_istream_set_size(input, 1);
		test_istream_set_max_buffer_size(input, 1);
		input2 = i_stream_create_base64_decoder(input);
		i_stream_unref(&input);
		test_inputs[i] = input2;
	};
	test_inputs[2] = NULL;

	try_input = istream_try_create(test_inputs, MIN_FULL_SIZE);

	test_assert(i_stream_read(try_input) == 0);
	test_assert(try_input->real_stream->parent != NULL);
	test_assert(i_stream_get_data_size(test_inputs[0]) == 0);
	test_assert(i_stream_get_data_size(test_inputs[1]) == 0);

	test_istream_set_size(test_inputs[0], 2);
	test_assert(i_stream_read(try_input) == 1);
	test_assert(i_stream_get_data_size(test_inputs[0]) == 1);
	test_assert(i_stream_get_data_size(test_inputs[1]) == 0);

	i_stream_unref(&test_inputs[0]);
	i_stream_unref(&test_inputs[1]);
	i_stream_unref(&try_input);

	test_end();
}

void test_istream_try(void)
{
	test_istream_try_normal();
	test_istream_try_empty();
	test_istream_try_buffer_full();
}
