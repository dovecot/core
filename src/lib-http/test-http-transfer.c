/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

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

struct http_transfer_chunked_test {
	const char *in;
	const char *out;
};

/* Valid transfer_chunked tests */
struct http_transfer_chunked_test valid_transfer_chunked_tests[] = {
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

unsigned int valid_transfer_chunked_test_count =
	N_ELEMENTS(valid_transfer_chunked_tests);

static void test_http_transfer_chunked_valid(void)
{
	struct istream *input, *chunked;
	struct ostream *output;
	buffer_t *payload_buffer;
	unsigned int i;

	payload_buffer = buffer_create_dynamic(default_pool, 1024);

	for (i = 0; i < valid_transfer_chunked_test_count; i++) T_BEGIN {
		const char *in, *out, *stream_out;

		in = valid_transfer_chunked_tests[i].in;
		out = valid_transfer_chunked_tests[i].out;

		test_begin(t_strdup_printf("http transfer_chunked valid [%d]", i));

		input = i_stream_create_from_data(in, strlen(in));
		chunked = http_transfer_chunked_istream_create(input);

		buffer_set_used_size(payload_buffer, 0);
		output = o_stream_create_buffer(payload_buffer);
		test_out("payload read", 
			o_stream_send_istream(output, chunked));
		o_stream_destroy(&output);
		stream_out = str_c(payload_buffer);

		test_out(t_strdup_printf("response->payload = %s",
			str_sanitize(stream_out, 80)),
			strcmp(stream_out, out) == 0);
		test_end();
	} T_END;

	buffer_free(&payload_buffer);
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_http_transfer_chunked_valid,
		NULL
	};
	return test_run(test_functions);
}
