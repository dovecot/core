/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "istream-failure-at.h"

#define TEST_DATA_LENGTH 128
#define TEST_ERRMSG "test-istream-failure-at error triggered"

void test_istream_failure_at(void)
{
	struct istream *input, *data_input;
	unsigned char test_data[TEST_DATA_LENGTH];
	unsigned int i;
	ssize_t ret;

	test_begin("istream failure at");
	for (i = 0; i < sizeof(test_data); i++)
		test_data[i] = i;
	data_input = i_stream_create_from_data(test_data, sizeof(test_data));
	for (i = 0; i < TEST_DATA_LENGTH; i++) {
		i_stream_seek(data_input, 0);
		input = i_stream_create_failure_at(data_input, i, TEST_ERRMSG);
		while ((ret = i_stream_read(input)) > 0)
			i_stream_skip(input, ret);
		test_assert_idx(ret == -1 && input->v_offset == i &&
				input->stream_errno == EIO &&
				strcmp(i_stream_get_error(input), TEST_ERRMSG) == 0, i);
		i_stream_destroy(&input);
	}
	/* shouldn't fail */
	i_stream_seek(data_input, 0);
	input = i_stream_create_failure_at(data_input, TEST_DATA_LENGTH, TEST_ERRMSG);
	while ((ret = i_stream_read(input)) > 0)
		i_stream_skip(input, ret);
	test_assert(ret == -1 && input->stream_errno == 0);
	i_stream_destroy(&input);
	/* fail at EOF */
	i_stream_seek(data_input, 0);
	input = i_stream_create_failure_at_eof(data_input, TEST_ERRMSG);
	while ((ret = i_stream_read(input)) > 0)
		i_stream_skip(input, ret);
	test_assert_idx(ret == -1 && input->v_offset == TEST_DATA_LENGTH &&
			input->stream_errno == EIO &&
			strcmp(i_stream_get_error(input), TEST_ERRMSG) == 0, i);
	i_stream_destroy(&input);
	i_stream_destroy(&data_input);
	test_end();
}
