/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-base64.h"

struct base64_istream_test {
	const char *input;
	const char *output;
	int stream_errno;
};

static const struct base64_istream_test base64_tests[] = {
	{ "aGVsbG8gd29ybGQ=", "hello world", 0 },
	{ "\naGVs\nbG8g\nd29y\nbGQ=\n", "hello world", 0 },
	{ "  aGVs    \r\n bG8g  \r\n   d29y  \t \r\n    bGQ= \r\n\r\n",
	  "hello world", 0 },
	{ "0JPQvtCy0L7RgNGPzIHRgiwg0YfRgtC+INC60YPRgCDQtNC+0Y/MgdGCLg==",
	  "\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
	  "\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
	  "\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
	  "\x81\xd1\x82\x2e", 0 },
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

static const struct base64_istream_test base64url_tests[] = {
	{ "aGVsbG8gd29ybGQ=", "hello world", 0 },
	{ "\naGVs\nbG8g\nd29y\nbGQ=\n", "hello world", 0 },
	{ "  aGVs    \r\n bG8g  \r\n   d29y  \t \r\n    bGQ= \r\n\r\n",
	  "hello world", 0 },
	{ "0JPQvtCy0L7RgNGPzIHRgiwg0YfRgtC-INC60YPRgCDQtNC-0Y_MgdGCLg==",
	  "\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
	  "\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
	  "\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
	  "\x81\xd1\x82\x2e", 0 },
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
decode_test(unsigned int base64_input_len,
	    struct istream *input_data, struct istream *input,
	    const char *output, int stream_errno)
{
	const unsigned char *data;
	size_t i, size;
	int ret = 0;

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
}

static void
decode_base64_test(const char *base64_input, const char *output,
		   int stream_errno)
{
	unsigned int base64_input_len = strlen(base64_input);
	struct istream *input_data, *input;

	input_data = test_istream_create_data(base64_input, base64_input_len);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_base64_decoder(input_data);

	decode_test(base64_input_len, input_data, input, output, stream_errno);

	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

static void
decode_base64url_test(const char *base64_input, const char *output,
		      int stream_errno)
{
	unsigned int base64_input_len = strlen(base64_input);
	struct istream *input_data, *input;

	input_data = test_istream_create_data(base64_input, base64_input_len);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_base64url_decoder(input_data);

	decode_test(base64_input_len, input_data, input, output, stream_errno);

	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

void test_istream_base64_decoder(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(base64_tests); i++) {
		const struct base64_istream_test *test = &base64_tests[i];

		test_begin(t_strdup_printf("istream base64 decoder %u", i+1));
		decode_base64_test(test->input, test->output,
				   test->stream_errno);
		test_end();
	}

	for (i = 0; i < N_ELEMENTS(base64url_tests); i++) {
		const struct base64_istream_test *test = &base64url_tests[i];

		test_begin(t_strdup_printf("istream base64url decoder %u",
					   i+1));
		decode_base64url_test(test->input, test->output,
				      test->stream_errno);
		test_end();
	}
}
