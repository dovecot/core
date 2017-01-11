/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "ostream.h"
#include "ostream-failure-at.h"

#define TEST_DATA_LENGTH 128
#define TEST_ERRMSG "test-ostream-failure-at error triggered"

void test_ostream_failure_at(void)
{
	unsigned char test_data[TEST_DATA_LENGTH];
	struct ostream *output, *buf_output;
	buffer_t *buf = buffer_create_dynamic(pool_datastack_create(), 256);
	unsigned int i;

	test_begin("ostream failure at");
	for (i = 0; i < sizeof(test_data); i++)
		test_data[i] = i;
	for (i = 0; i < TEST_DATA_LENGTH; i++) {
		buf_output = o_stream_create_buffer(buf);
		output = o_stream_create_failure_at(buf_output, i, TEST_ERRMSG);
		if (i > 0)
			test_assert(o_stream_send(output, test_data, sizeof(test_data)) == (int)i);
		test_assert_idx(o_stream_send(output, test_data, sizeof(test_data)) == -1 &&
				output->offset == i &&
				output->stream_errno == EIO &&
				strcmp(o_stream_get_error(output), TEST_ERRMSG) == 0, i);
		o_stream_destroy(&output);
		o_stream_destroy(&buf_output);
	}
	/* shouldn't fail */
	buf_output = o_stream_create_buffer(buf);
	output = o_stream_create_failure_at(buf_output, TEST_DATA_LENGTH, TEST_ERRMSG);
	test_assert(o_stream_send(output, test_data, sizeof(test_data)) == TEST_DATA_LENGTH);
	test_assert(o_stream_flush(output) > 0 &&
		    output->offset == TEST_DATA_LENGTH &&
		    output->stream_errno == 0);
	o_stream_destroy(&output);
	o_stream_destroy(&buf_output);

	/* fail at flush */
	buf_output = o_stream_create_buffer(buf);
	output = o_stream_create_failure_at_flush(buf_output, TEST_ERRMSG);
	test_assert(o_stream_send(output, test_data, sizeof(test_data)) == TEST_DATA_LENGTH);
	test_assert(o_stream_flush(output) < 0 && output->stream_errno == EIO &&
		    strcmp(o_stream_get_error(output), TEST_ERRMSG) == 0);
	o_stream_destroy(&output);
	o_stream_destroy(&buf_output);
	test_end();
}
