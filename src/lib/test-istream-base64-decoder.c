/* Copyright (c) 2010-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-base64.h"

static const struct {
	const char *input;
	const char *output;
	int stream_errno;
} tests[] = {
	{ "aGVsbG8gd29ybGQ=", "hello world", 0 },
	{ "\naGVs\nbG8g\nd29y\nbGQ=\n", "hello world", 0 },
	{ "  aGVs    \r\n bG8g  \r\n   d29y  \t \r\n    bGQ= \r\n\r\n", "hello world", 0 },
	{ "\r", "", 0 },
	{ "\n", "", 0 },
	{ "\r\n", "", 0 },
	{ "  ", "", 0 },
	{ "foo", "", EPIPE },
	{ "foo ", "", EINVAL },
	{ "Zm9vC", "foo", EPIPE },
	{ "Zm9v!", "foo", EINVAL },
	{ "Zm9!v", "", EINVAL },
	{ "Zm9 v", "", EINVAL },
	{ "Zm 9v", "", EINVAL },
	{ "Z m9v", "", EINVAL },
};

static void
decode_test(const char *base64_input, const char *output, int stream_errno)
{
	unsigned int base64_input_len = strlen(base64_input);
	struct istream *input_data, *input;
	const unsigned char *data;
	size_t i, size;
	int ret = 0;

	input_data = test_istream_create_data(base64_input, base64_input_len);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_base64_decoder(input_data);

	for (i = 1; i <= base64_input_len; i++) {
		test_istream_set_size(input_data, i);
		while ((ret = i_stream_read(input)) > 0) ;
		if (ret == -1 && stream_errno != 0)
			break;
		test_assert(ret == 0);
	}
	if (ret == 0) {
		test_istream_set_allow_eof(input_data, TRUE);
		while ((ret = i_stream_read(input)) > 0) ;
	}
	test_assert(ret == -1);
	test_assert(input->stream_errno == stream_errno);

	data = i_stream_get_data(input, &size);
	test_assert(size == strlen(output));
	if (size > 0)
		test_assert(memcmp(data, output, size) == 0);
	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

void test_istream_base64_decoder(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("istream base64 decoder %u", i+1));
		decode_test(tests[i].input, tests[i].output, tests[i].stream_errno);
		test_end();
	}
}
