/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-base64.h"

static struct test {
	const char *input;
	unsigned int chars_per_line;
	bool crlf;
	const char *output;
} tests[] = {
	{ "hello world", 80, FALSE, "aGVsbG8gd29ybGQ=" },
	{ "hello world", 4, FALSE, "aGVs\nbG8g\nd29y\nbGQ=" },
	{ "hello world", 4, TRUE, "aGVs\r\nbG8g\r\nd29y\r\nbGQ=", },
};

static const char *hello = "hello world";

static void encode_test(const char *text, unsigned int chars_per_line,
			bool crlf, const char *output)
{
	unsigned int i, text_len = strlen(text);
	struct istream *input, *input_data;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	input_data = test_istream_create_data(text, text_len);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_base64_encoder(input_data, chars_per_line, crlf);

	for (i = 1; i <= text_len; i++) {
		test_istream_set_size(input_data, i);
		while ((ret = i_stream_read(input)) > 0) ;
		test_assert(ret == 0);
	}
	test_istream_set_allow_eof(input_data, TRUE);
	while ((ret = i_stream_read(input)) > 0) ;
	test_assert(ret == -1);

	data = i_stream_get_data(input, &size);
	test_assert(size == strlen(output) && memcmp(data, output, size) == 0);

	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

static void
test_istream_base64_encoder_seek(const char *textin, const char *textout)
{
	unsigned int offset, len = strlen(textout);
	struct istream *input, *input_data;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	input_data = i_stream_create_from_data(textin, strlen(textin));
	input = i_stream_create_base64_encoder(input_data, 4, TRUE);

	while (i_stream_read(input) > 0) ;
	i_stream_skip(input, i_stream_get_data_size(input));

	for (offset = 0; offset < len; offset++) {
		i_stream_seek(input, offset);
		while ((ret = i_stream_read(input)) > 0) ;
		test_assert(ret == -1);

		data = i_stream_get_data(input, &size);
		test_assert(size == len-offset);
		test_assert(memcmp(data, textout+offset, size) == 0);
		i_stream_skip(input, size);
	}

	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

void test_istream_base64_encoder(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("istream base64 decoder %u", i+1));
		encode_test(tests[i].input, tests[i].chars_per_line,
			    tests[i].crlf, tests[i].output);
		test_end();
	}
	test_begin("istream base64 encoder seek");
	test_istream_base64_encoder_seek(hello, "aGVs\r\nbG8g\r\nd29y\r\nbGQ=");
	test_end();
}
