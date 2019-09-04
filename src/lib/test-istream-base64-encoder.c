/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-base64.h"

struct base64_istream_test {
	const char *input;
	unsigned int chars_per_line;
	bool crlf;
	const char *output;
};

static const struct base64_istream_test base64_tests[] = {
	{ "", 80, FALSE, "" },
	{ "1", 80, FALSE, "MQ==" },
	{ "12", 80, FALSE, "MTI=" },
	{ "123", 80, FALSE, "MTIz" },
	{ "1234", 80, FALSE, "MTIzNA==" },
	{ "12345", 80, FALSE, "MTIzNDU=" },
	{ "hello world", 80, FALSE, "aGVsbG8gd29ybGQ=" },
	{ "hello world", 4, FALSE, "aGVs\nbG8g\nd29y\nbGQ=" },
	{ "hello world", 4, TRUE, "aGVs\r\nbG8g\r\nd29y\r\nbGQ=" },
	{ "hello worlds", 80, FALSE, "aGVsbG8gd29ybGRz" },
	{ "hello worlds", 4, FALSE, "aGVs\nbG8g\nd29y\nbGRz" },
	{ "hello worlds", 4, TRUE, "aGVs\r\nbG8g\r\nd29y\r\nbGRz" },
	{ "hell world", 80, FALSE, "aGVsbCB3b3JsZA==" },
	{ "hell world", 4, FALSE, "aGVs\nbCB3\nb3Js\nZA==" },
	{ "hell world", 4, TRUE, "aGVs\r\nbCB3\r\nb3Js\r\nZA==" },
	{ "hello to the world!!", 80, FALSE,
		"aGVsbG8gdG8gdGhlIHdvcmxkISE=" },
	{ "hello to the world!!", 8, FALSE,
		"aGVsbG8g\ndG8gdGhl\nIHdvcmxk\nISE=" },
	{ "hello to the world!!", 8, TRUE,
		"aGVsbG8g\r\ndG8gdGhl\r\nIHdvcmxk\r\nISE=" },
	{ "\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
	  "\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
	  "\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
	  "\x81\xd1\x82\x2e", 80, FALSE,
	  "0JPQvtCy0L7RgNGPzIHRgiwg0YfRgtC+INC60YPRgCDQtNC+0Y/MgdGCLg==" },
};

static const struct base64_istream_test base64url_tests[] = {
	{ "", 80, FALSE, "" },
	{ "1", 80, FALSE, "MQ==" },
	{ "12", 80, FALSE, "MTI=" },
	{ "123", 80, FALSE, "MTIz" },
	{ "1234", 80, FALSE, "MTIzNA==" },
	{ "12345", 80, FALSE, "MTIzNDU=" },
	{ "hello world", 80, FALSE, "aGVsbG8gd29ybGQ=" },
	{ "hello world", 4, FALSE, "aGVs\nbG8g\nd29y\nbGQ=" },
	{ "hello world", 4, TRUE, "aGVs\r\nbG8g\r\nd29y\r\nbGQ=" },
	{ "hello worlds", 80, FALSE, "aGVsbG8gd29ybGRz" },
	{ "hello worlds", 4, FALSE, "aGVs\nbG8g\nd29y\nbGRz" },
	{ "hello worlds", 4, TRUE, "aGVs\r\nbG8g\r\nd29y\r\nbGRz" },
	{ "hell world", 80, FALSE, "aGVsbCB3b3JsZA==" },
	{ "hell world", 4, FALSE, "aGVs\nbCB3\nb3Js\nZA==" },
	{ "hell world", 4, TRUE, "aGVs\r\nbCB3\r\nb3Js\r\nZA==" },
	{ "hello to the world!!", 80, FALSE,
		"aGVsbG8gdG8gdGhlIHdvcmxkISE=" },
	{ "hello to the world!!", 8, FALSE,
		"aGVsbG8g\ndG8gdGhl\nIHdvcmxk\nISE=" },
	{ "hello to the world!!", 8, TRUE,
		"aGVsbG8g\r\ndG8gdGhl\r\nIHdvcmxk\r\nISE=" },
	{ "\xd0\x93\xd0\xbe\xd0\xb2\xd0\xbe\xd1\x80\xd1\x8f\xcc"
	  "\x81\xd1\x82\x2c\x20\xd1\x87\xd1\x82\xd0\xbe\x20\xd0"
	  "\xba\xd1\x83\xd1\x80\x20\xd0\xb4\xd0\xbe\xd1\x8f\xcc"
	  "\x81\xd1\x82\x2e", 80, FALSE,
	  "0JPQvtCy0L7RgNGPzIHRgiwg0YfRgtC-INC60YPRgCDQtNC-0Y_MgdGCLg==" },
};

static const char *hello = "hello world";

static void encode_test(unsigned int text_len,
			struct istream *input, struct istream *input_data,
			const char *output)
{
	unsigned int i;
	const unsigned char *data;
	uoff_t stream_size;
	size_t size;
	ssize_t ret;

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

	ret = i_stream_get_size(input, TRUE, &stream_size);
	test_assert(ret > 0);
	test_assert(size == stream_size);
}

static void
encode_base64_test(const char *text, unsigned int chars_per_line,
		   bool crlf, const char *output)
{
	unsigned int text_len = strlen(text);
	struct istream *input, *input_data;

	input_data = test_istream_create_data(text, text_len);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_base64_encoder(input_data, chars_per_line,
					       crlf);

	encode_test(text_len, input, input_data, output);

	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

static void
encode_base64url_test(const char *text, unsigned int chars_per_line,
		      bool crlf, const char *output)
{
	unsigned int text_len = strlen(text);
	struct istream *input, *input_data;

	input_data = test_istream_create_data(text, text_len);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_base64url_encoder(input_data, chars_per_line,
						  crlf);

	encode_test(text_len, input, input_data, output);

	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

static void
test_encoder_seek(struct istream *input, const char *textout)
{
	unsigned int offset, len = strlen(textout);
	const unsigned char *data;
	size_t size;
	ssize_t ret;

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
}

static void
test_istream_base64_encoder_seek(const char *textin, const char *textout)
{
	struct istream *input, *input_data;

	input_data = i_stream_create_from_data(textin, strlen(textin));
	input = i_stream_create_base64_encoder(input_data, 4, TRUE);

	test_encoder_seek(input, textout);

	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

static void
test_istream_base64url_encoder_seek(const char *textin, const char *textout)
{
	struct istream *input, *input_data;

	input_data = i_stream_create_from_data(textin, strlen(textin));
	input = i_stream_create_base64url_encoder(input_data, 4, TRUE);

	test_encoder_seek(input, textout);

	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

void test_istream_base64_encoder(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(base64_tests); i++) {
		const struct base64_istream_test *test = &base64_tests[i];

		test_begin(t_strdup_printf(
			"istream base64 encoder %u", i+1));
		encode_base64_test(test->input, test->chars_per_line,
				   test->crlf, test->output);
		test_end();
	}

	for (i = 0; i < N_ELEMENTS(base64url_tests); i++) {
		const struct base64_istream_test *test = &base64url_tests[i];

		test_begin(t_strdup_printf(
			"istream base64url encoder %u", i+1));
		encode_base64url_test(test->input, test->chars_per_line,
				      test->crlf, test->output);
		test_end();
	}

	test_begin("istream base64 encoder seek");
	test_istream_base64_encoder_seek(
		hello, "aGVs\r\nbG8g\r\nd29y\r\nbGQ=");
	test_end();

	test_begin("istream base64url encoder seek");
	test_istream_base64url_encoder_seek(
		hello, "aGVs\r\nbG8g\r\nd29y\r\nbGQ=");
	test_end();
}
