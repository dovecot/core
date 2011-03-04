/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-internal.h"
#include "istream-base64-encoder.h"

static const char *hello = "hello world";

static const char *
encode(const char *text, unsigned int chars_per_line, bool crlf)
{
	struct istream *input, *input_data;
	const char *reply;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	input_data = i_stream_create_from_data(text, strlen(text));
	input = i_stream_create_base64_encoder(input_data, chars_per_line, crlf);
	while ((ret = i_stream_read(input)) > 0) ;
	test_assert(ret == -1);

	data = i_stream_get_data(input, &size);
	reply = t_strndup(data, size);

	i_stream_unref(&input);
	i_stream_unref(&input_data);
	return reply;
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
	(void)i_stream_get_data(input, &size);
	i_stream_skip(input, size);

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
	test_begin("istream base64 encoder");
	test_assert(strcmp(encode(hello, 80, FALSE), "aGVsbG8gd29ybGQ=") == 0);
	test_assert(strcmp(encode(hello, 4, FALSE), "aGVs\nbG8g\nd29y\nbGQ=") == 0);
	test_assert(strcmp(encode(hello, 4, TRUE), "aGVs\r\nbG8g\r\nd29y\r\nbGQ=") == 0);
	test_istream_base64_encoder_seek(hello, "aGVs\r\nbG8g\r\nd29y\r\nbGQ=");
	test_end();
}
