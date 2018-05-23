/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "str.h"
#include "strfuncs.h"
#include "str-sanitize.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"
#include "http-transfer.h"

#include <time.h>

struct http_transfer_chunked_input_test {
	const char *in;
	const char *out;
};

/* Valid transfer_chunked input tests */
static struct http_transfer_chunked_input_test
valid_transfer_chunked_input_tests[] = {
	{	.in = "1E\r\n"
			"This is a simple test payload."
			"\r\n"
			"0\r\n"
			"\r\n",
		.out =
			"This is a simple test payload."
	},
	{	.in = "20\r\n"
			"This is a longer test payload..."
			"\r\n"
			"23\r\n"
			"...spread over two separate chunks."
			"\r\n"
			"0\r\n"
			"\r\n",
		.out =
			"This is a longer test payload..."
			"...spread over two separate chunks."
	},
	{	.in = "26\r\n"
			"This is an even longer test payload..."
			"\r\n"
			"27\r\n"
			"...spread over three separate chunks..."
			"\r\n"
			"1F\r\n"
			"...and also includes a trailer."
			"\r\n"
			"0\r\n"
			"Checksum: adgfef3fdaf3daf3dfaf3ff3fdag\r\n"
			"X-Dovecot: Whatever\r\n"
			"\r\n",
		.out =
			"This is an even longer test payload..."
			"...spread over three separate chunks..."
			"...and also includes a trailer."
	},
	{	.in = "26\n"
			"This is an even longer test payload..."
			"\n"
			"27\n"
			"...spread over three separate chunks..."
			"\n"
			"1F\n"
			"...and also includes a trailer."
			"\n"
			"0\n"
			"Checksum: adgfef3fdaf3daf3dfaf3ff3fdag\n"
			"X-Dovecot: Whatever\n"
			"\n",
		.out =
			"This is an even longer test payload..."
			"...spread over three separate chunks..."
			"...and also includes a trailer."
	}
};

static unsigned int valid_transfer_chunked_input_test_count =
	N_ELEMENTS(valid_transfer_chunked_input_tests);

static void test_http_transfer_chunked_input_valid(void)
{
	struct istream *input, *chunked;
	struct ostream *output;
	buffer_t *payload_buffer;
	unsigned int i;

	payload_buffer = buffer_create_dynamic(default_pool, 1024);

	for (i = 0; i < valid_transfer_chunked_input_test_count; i++) T_BEGIN {
		const char *in, *out, *stream_out;

		in = valid_transfer_chunked_input_tests[i].in;
		out = valid_transfer_chunked_input_tests[i].out;

		test_begin(t_strdup_printf("http transfer_chunked input valid [%d]", i));

		input = i_stream_create_from_data(in, strlen(in));
		chunked = http_transfer_chunked_istream_create(input, 0);
		i_stream_unref(&input);

		buffer_set_used_size(payload_buffer, 0);
		output = o_stream_create_buffer(payload_buffer);
		test_out("payload read", o_stream_send_istream(output, chunked) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED
			&& chunked->stream_errno == 0);
		o_stream_destroy(&output);
		i_stream_unref(&chunked);
		stream_out = str_c(payload_buffer);

		test_out(t_strdup_printf("response->payload = %s",
			str_sanitize(stream_out, 80)),
			strcmp(stream_out, out) == 0);
		test_end();
	} T_END;

	buffer_free(&payload_buffer);
}

/* Invalid transfer_chunked input tests */
static const char *
invalid_transfer_chunked_input_tests[] = {
	// invalid size
	"1X\r\n"
	"This is a simple test payload."
	"\r\n"
	"0\r\n"
	"\r\n",
	// invalid end
	"1E\r\n"
	"This is a simple test payload."
	"\r\n"
	"0\r\n"
	"ah\r\n",
	// invalid size
	"20\r\n"
	"This is a longer test payload..."
	"\r\n"
	"2q\r\n"
	"...spread over two separate chunks."
	"\r\n"
	"0\r\n"
	"\r\n",
	// invalid end
	"20\r\n"
	"This is a longer test payload..."
	"\r\n"
	"23\r\n"
	"...spread over two separate chunks."
	"\r\n"
	"0\r\n",
	// invalid last chunk
	"20\r\n"
	"This is a longer test payload..."
	"\r\n"
	"23\r\n"
	"...spread over two separate chunks."
	"\r\n"
	"4\r\n"
	"\r\n",
	// invalid trailer
	"26\r\n"
	"This is an even longer test payload..."
	"\r\n"
	"27\r\n"
	"...spread over three separate chunks..."
	"\r\n"
	"1F\r\n"
	"...and also includes a trailer."
	"\r\n"
	"0\r\n"
	"Checksum adgfef3fdaf3daf3dfaf3ff3fdag\r\n"
	"\r\n"
};

static unsigned int invalid_transfer_chunked_input_test_count =
	N_ELEMENTS(invalid_transfer_chunked_input_tests);

static void test_http_transfer_chunked_input_invalid(void)
{
	struct istream *input, *chunked;
	struct ostream *output;
	buffer_t *payload_buffer;
	unsigned int i;

	payload_buffer = buffer_create_dynamic(default_pool, 1024);

	for (i = 0; i < invalid_transfer_chunked_input_test_count; i++) T_BEGIN {
		const char *in;

		in = invalid_transfer_chunked_input_tests[i];

		test_begin(t_strdup_printf("http transfer_chunked input invalid [%d]", i));

		input = i_stream_create_from_data(in, strlen(in));
		chunked = http_transfer_chunked_istream_create(input, 0);
		i_stream_unref(&input);

		buffer_set_used_size(payload_buffer, 0);
		output = o_stream_create_buffer(payload_buffer);
		o_stream_nsend_istream(output, chunked);
		test_out("payload read failure", chunked->stream_errno != 0);
		i_stream_unref(&chunked);
		o_stream_destroy(&output);

		test_end();
	} T_END;

	buffer_free(&payload_buffer);
}

/* Valid transfer_chunked output tests */
static const char *valid_transfer_chunked_output_tests[] = {
	/* The maximum chunk size is set to 16. These tests are tuned to some border
	   cases 
	*/
	"A small payload",  // 15 bytes
	"A longer payload", // 16 bytes
	"A lengthy payload", // 17 bytes
	/* Others */
	"This is a test payload with lots of nonsense.",
	"Yet another payload.",
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
	"This a very long repetitive payload. This a very long repetitive payload. "
}; 

static unsigned int valid_transfer_chunked_output_test_count =
	N_ELEMENTS(valid_transfer_chunked_output_tests);

static void test_http_transfer_chunked_output_valid(void)
{
	struct istream *input, *ichunked;
	struct ostream *output, *ochunked;
	buffer_t *chunked_buffer, *plain_buffer;
	unsigned int i;

	chunked_buffer = buffer_create_dynamic(default_pool, 1024);
	plain_buffer = buffer_create_dynamic(default_pool, 1024);

	for (i = 0; i < valid_transfer_chunked_output_test_count; i++) T_BEGIN {
		const char *data, *stream_out;
		const unsigned char *rdata;
		size_t rsize;
		ssize_t ret;

		data = valid_transfer_chunked_output_tests[i];

		test_begin(t_strdup_printf("http transfer_chunked output valid [%d]", i));

		/* create input stream */
		input = i_stream_create_from_data(data, strlen(data));

		/* create buffer output stream */
		buffer_set_used_size(chunked_buffer, 0);
		output = o_stream_create_buffer(chunked_buffer);

		/* create chunked output stream */
		ochunked = http_transfer_chunked_ostream_create(output);

		/* send input through chunked stream; chunk size is limited */
		for (;;) {
			ret = i_stream_read_more(input, &rdata, &rsize);
			if (ret < 0) {
				if (input->eof)
					ret = 1;
				break;
			}
			if (rsize == 0) 
				break;
			if (rsize > 16)
				rsize = 16;

			ret = o_stream_send(ochunked, rdata, rsize);
			if (ret < 0)
				break;

			if ((size_t)ret != rsize) {
				ret = -1;
				break;
			}

			i_stream_skip(input, ret);
		}

		/* cleanup streams */
		test_out("payload chunk", ret > 0);
		o_stream_destroy(&ochunked);
		o_stream_destroy(&output);
		i_stream_destroy(&input);
		
		/* create chunked input stream */
		input = i_stream_create_from_data
			(chunked_buffer->data, chunked_buffer->used);
		ichunked = http_transfer_chunked_istream_create(input, 0);

		/* read back chunk */
		buffer_set_used_size(plain_buffer, 0);
		output = o_stream_create_buffer(plain_buffer);
		test_out("payload unchunk",
			o_stream_send_istream(output, ichunked) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED
			&& ichunked->stream_errno == 0);
		o_stream_destroy(&output);
		i_stream_destroy(&ichunked);
		i_stream_destroy(&input);

		/* test output */
		stream_out = str_c(plain_buffer);
		test_out(t_strdup_printf("response->payload = %s",
			str_sanitize(stream_out, 80)),
			strcmp(stream_out, data) == 0);
		test_end();
	} T_END;

	buffer_free(&chunked_buffer);
	buffer_free(&plain_buffer);
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_http_transfer_chunked_input_valid,
		test_http_transfer_chunked_input_invalid,
		test_http_transfer_chunked_output_valid,
		NULL
	};
	return test_run(test_functions);
}
