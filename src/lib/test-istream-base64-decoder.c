/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-base64.h"
#include "istream-sized.h"
#include "base64.h"

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
	{ "foo", "\x7e\x8a", EPIPE },
	{ "foo ","\x7e\x8a", EPIPE },
	{ "Zm9vC", "foo", EPIPE },
	{ "Zm9v!", "foo", EINVAL },
	{ "Zm9!v", "fo", EINVAL },
	{ "Zm9 v", "foo", 0 },
	{ "Zm 9v", "foo", 0 },
	{ "Z m9v", "foo", 0 },
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
	{ "foo", "\x7e\x8a", EPIPE },
	{ "foo ","\x7e\x8a", EPIPE },
	{ "Zm9vC", "foo", EPIPE },
	{ "Zm9v!", "foo", EINVAL },
	{ "Zm9!v", "fo", EINVAL },
	{ "Zm9 v", "foo", 0 },
	{ "Zm 9v", "foo", 0 },
	{ "Z m9v", "foo", 0 },
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

static void
test_istream_base64_io_random(void)
{
	unsigned char in_buf[2048];
	size_t in_buf_size;
	buffer_t *out_buf;
	unsigned int i, j;
	int ret;

	out_buf = t_buffer_create(sizeof(in_buf));

	test_begin("istream base64 random I/O");

	for (i = 0; i < 4000; i++) {
		struct istream *input1, *input2, *input3, *input4, *input5;
		struct istream *sinput1, *sinput2, *sinput3, *sinput4;
		struct istream *top_input;
		const unsigned char *data;
		unsigned int chpl1, chpl2;
		unsigned char sized_streams;
		size_t size;
		struct base64_encoder b64enc;

		/* Initialize test data */
		in_buf_size = i_rand_limit(sizeof(in_buf));
		for (j = 0; j < in_buf_size; j++)
			in_buf[j] = i_rand();

		/* Reset final output buffer */
		buffer_set_used_size(out_buf, 0);

		/* Determine line lengths */
		chpl1 = i_rand_limit(30)*4;
		chpl2 = i_rand_limit(30)*4;

		/* Create stream for test data */
		input1 = i_stream_create_from_data(in_buf, in_buf_size);
		i_stream_set_name(input1, "[data]");

		/* Determine which stages have sized streams */
		sized_streams = i_rand_minmax(0x00, 0x0f);

		/* Create first encoder stream */
		input2 = i_stream_create_base64_encoder(input1, chpl1, FALSE);
		i_stream_set_name(input2, "[base64_encoder #1]");

		if (HAS_ALL_BITS(sized_streams, BIT(0))) {
			/* Wrap the first encoder stream in a sized stream to
			   check size and trigger any buffer overflow problems
			 */
			base64_encode_init(&b64enc, &base64_scheme, 0, chpl1);
			sinput1 = i_stream_create_sized(input2,
				base64_get_full_encoded_size(&b64enc,
							     in_buf_size));
			i_stream_set_name(sinput1, "[sized #1]");
		} else {
			sinput1 = input2;
			i_stream_ref(sinput1);
		}

		/* Create first decoder stream */
		input3 = i_stream_create_base64_decoder(sinput1);
		i_stream_set_name(input3, "[base64_decoder #1]");

		if (HAS_ALL_BITS(sized_streams, BIT(1))) {
			/* Wrap the first decoder stream in a sized stream to
			   check size and trigger any buffer overflow problems
			 */
			sinput2 = i_stream_create_sized(input3, in_buf_size);
			i_stream_set_name(sinput2, "[sized #2]");
		} else {
			sinput2 = input3;
			i_stream_ref(sinput2);
		}

		/* Create second encoder stream */
		input4 = i_stream_create_base64_encoder(sinput2, chpl2, FALSE);
		i_stream_set_name(input4, "[base64_encoder #2]");

		if (HAS_ALL_BITS(sized_streams, BIT(2))) {
			/* Wrap the second encoder stream in a sized stream to
			   check size and trigger any buffer overflow problems
			 */
			base64_encode_init(&b64enc, &base64_scheme, 0, chpl2);
			sinput3 = i_stream_create_sized(input4,
				base64_get_full_encoded_size(&b64enc,
							    in_buf_size));
			i_stream_set_name(sinput3, "[sized #3]");
		} else {
			sinput3 = input4;
			i_stream_ref(sinput3);
		}

		/* Create second deoder stream */
		input5 = i_stream_create_base64_decoder(sinput3);
		i_stream_set_name(input5, "[base64_decoder #2]");

		if (HAS_ALL_BITS(sized_streams, BIT(3))) {
			/* Wrap the second decoder stream in a sized stream to
			   check size and trigger any buffer overflow problems
			 */
			sinput4 = i_stream_create_sized(input5, in_buf_size);
			i_stream_set_name(sinput4, "[sized #4]");
		} else {
			sinput4 = input5;
			i_stream_ref(sinput4);
		}


		/* Assign random buffer sizes */
		i_stream_set_max_buffer_size(input5, i_rand_minmax(4, 512));
		i_stream_set_max_buffer_size(input4, i_rand_minmax(4, 512));
		i_stream_set_max_buffer_size(input3, i_rand_minmax(4, 512));
		i_stream_set_max_buffer_size(input2, i_rand_minmax(4, 512));

		/* Read the outer stream in full with random increments. */
		top_input = sinput4;
		while ((ret = i_stream_read_more(
			top_input, &data, &size)) > 0) {
			size_t ch = i_rand_limit(512);

			size = I_MIN(size, ch);
			buffer_append(out_buf, data, size);
			i_stream_skip(top_input, size);
		}
		if (ret < 0 && top_input->stream_errno == 0) {
			data = i_stream_get_data(top_input, &size);
			if (size > 0) {
				buffer_append(out_buf, data, size);
				i_stream_skip(top_input, size);
			}
		}

		/* Assert stream status */
		test_assert_idx(ret < 0 && top_input->stream_errno == 0, i);
		/* Assert input/output equality */
		test_assert_idx(out_buf->used == in_buf_size &&
				memcmp(in_buf, out_buf->data, in_buf_size) == 0,
				i);

		/* Clean up */
		i_stream_unref(&input1);
		i_stream_unref(&input2);
		i_stream_unref(&input3);
		i_stream_unref(&input4);
		i_stream_unref(&input5);
		i_stream_unref(&sinput1);
		i_stream_unref(&sinput2);
		i_stream_unref(&sinput3);
		i_stream_unref(&sinput4);
	}
	test_end();
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

	test_istream_base64_io_random();
}
