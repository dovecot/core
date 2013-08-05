/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"
#include "http-response-parser.h"

#include <time.h>

struct http_response_parse_test {
	const char *response;
	unsigned char version_major;
	unsigned char version_minor;
	unsigned int status;
	uoff_t content_length;
	const char *payload;
};

/* Valid header tests */

static const struct http_response_parse_test
valid_response_parse_tests[] = {
	{ .response =
			"HTTP/1.1 200 OK\r\n"
			"Date: Sun, 07 Oct 2012 13:02:27 GMT\r\n"
			"Server: Apache/2.2.16 (Debian)\r\n"
			"Last-Modified: Tue, 18 Sep 2012 19:31:41 GMT\r\n"
			"Etag: \"2a8400c-10751f-4c9fef0858140\"\r\n"
			"Accept-Ranges: bytes\r\n"
			"Content-Length: 33\r\n"
			"Keep-Alive: timeout=15, max=100\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Type: text/plain\r\n"
			"\r\n"
			"This is a piece of stupid text.\r\n",
		.status = 200,
		.payload = "This is a piece of stupid text.\r\n"
	},{ 
		.response =
			"HTTP/1.1 200 OK\r\n"
			"Date: Sun, 07 Oct 2012 13:02:27 GMT\r\n"
			"Server: Apache/2.2.16 (Debian)\r\n"
			"Last-Modified: Tue, 18 Sep 2012 19:31:41 GMT\r\n"
			"Etag: \"2a8400c-10751f-4c9fef0858140\"\r\n"
			"Accept-Ranges: bytes\r\n"
			"Content-Length: 33\r\n"
			"Keep-Alive: timeout=15, max=100\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Type: text/plain\r\n"
			"\r\n"
			"This is a piece of stupid text.\r\n"
			"HTTP/1.1 200 OK\r\n"
			"Date: Sun, 07 Oct 2012 13:02:27 GMT\r\n"
			"Server: Apache/2.2.16 (Debian)\r\n"
			"Last-Modified: Tue, 18 Sep 2012 19:31:41 GMT\r\n"
			"Etag: \"2a8400c-10751f-4c9fef0858140\"\r\n"
			"Accept-Ranges: bytes\r\n"
			"Content-Length: 43\r\n"
			"Keep-Alive: timeout=15, max=100\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Type: text/plain\r\n"
			"\r\n"
			"This is a piece of even more stupid text.\r\n",
		.status = 200,
		.payload = "This is a piece of even more stupid text.\r\n"
	},{
		.response =
			"HTTP/1.1 401 Authorization Required\r\n"
			"Date: Sun, 07 Oct 2012 19:52:03 GMT\r\n"
			"Server: Apache/2.2.16 (Debian) PHP/5.3.3-7+squeeze14\r\n"
			"WWW-Authenticate: Basic realm=\"Munin\"\r\n"
			"Vary: Accept-Encoding\r\n"
			"Content-Encoding: gzip\r\n"
			"Content-Length: 5\r\n"
			"Keep-Alive: timeout=15, max=99\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Type: text/html; charset=iso-8859-1\r\n"
			"\r\n"
			"Frop!",
		.status = 401,
		.payload = "Frop!"
	}
};

unsigned int valid_response_parse_test_count =
	N_ELEMENTS(valid_response_parse_tests);

static void test_http_response_parse_valid(void)
{
	unsigned int i;
	buffer_t *payload_buffer = buffer_create_dynamic(default_pool, 1024);

	for (i = 0; i < valid_response_parse_test_count; i++) T_BEGIN {
		struct istream *input;
		struct ostream *output;
		const struct http_response_parse_test *test;
		struct http_response_parser *parser;
		struct http_response *response = NULL;
		const char *response_text, *payload, *error;
		unsigned int pos, response_text_len;
		int ret = 0;

		test = &valid_response_parse_tests[i];
		response_text = test->response;
		response_text_len = strlen(response_text);
		input = test_istream_create_data(response_text, response_text_len);
		parser = http_response_parser_init(input);

		test_begin(t_strdup_printf("http response valid [%d]", i));

		payload = NULL;
		for (pos = 0; pos < response_text_len && ret == 0; pos++) {
			test_istream_set_size(input, pos);
			ret = http_response_parse_next(parser, FALSE, &response, &error);
		}
		test_istream_set_size(input, response_text_len);
		while (ret > 0) {
			if (response->payload != NULL) {
				buffer_set_used_size(payload_buffer, 0);
				output = o_stream_create_buffer(payload_buffer);
				test_out("payload receive", 
					o_stream_send_istream(output, response->payload));
				o_stream_destroy(&output);
				payload = str_c(payload_buffer);
			} else {
				payload = NULL;
			}
			ret = http_response_parse_next(parser, FALSE, &response, &error);
		}

		test_out("parse success", ret == 0);
		
		if (ret == 0) {
			/* verify last response only */
			i_assert(response != NULL);
			test_out(t_strdup_printf("response->status = %d",test->status),
					response->status == test->status);
			if (payload == NULL || test->payload == NULL) {
				test_out(t_strdup_printf("response->payload = %s",
					str_sanitize(payload, 80)),
					payload == test->payload);
			} else {
				test_out(t_strdup_printf("response->payload = %s",
					str_sanitize(payload, 80)),
					strcmp(payload, test->payload) == 0);
			}
		}
		test_end();
		http_response_parser_deinit(&parser);
	} T_END;

	buffer_free(&payload_buffer);
}

static const char *invalid_response_parse_tests[] = {
	"XMPP/1.0 302 Found\r\n"
	"Location: http://www.example.nl/\r\n"
	"Cache-Control: private\r\n",
	"HTTP/1.1  302 Found\r\n"
	"Location: http://www.example.nl/\r\n"
	"Cache-Control: private\r\n",
	"HTTP/1.1 ABC Found\r\n"
	"Location: http://www.example.nl/\r\n"
	"Cache-Control: private\r\n",
	"HTTP/1.1 302 \177\r\n"
	"Location: http://www.example.nl/\r\n"
	"Cache-Control: private\r\n",
	"HTTP/1.1 302 Found\n\r"
	"Location: http://www.example.nl/\n\r"
	"Cache-Control: private\n\r"
};

static unsigned char invalid_response_with_nuls[] =
	"HTTP/1.1 200 OK\r\n"
	"Server: text\0server\r\n"
	"\r\n";

unsigned int invalid_response_parse_test_count =
	N_ELEMENTS(invalid_response_parse_tests);

static void test_http_response_parse_invalid(void)
{
	struct http_response_parser *parser;
	struct http_response *response;
	const char *response_text, *error;
	struct istream *input;
	int ret;
	unsigned int i;

	for (i = 0; i < invalid_response_parse_test_count; i++) T_BEGIN {
		const char *test;

		test = invalid_response_parse_tests[i];
		response_text = test;
		input = i_stream_create_from_data(response_text, strlen(response_text));
		parser = http_response_parser_init(input);

		test_begin(t_strdup_printf("http response invalid [%d]", i));

		while ((ret=http_response_parse_next(parser, FALSE, &response, &error)) > 0);

		test_assert(ret < 0);
		test_end();
		http_response_parser_deinit(&parser);
	} T_END;

	/* parse failure guarantees http_response_header.size equals
	   strlen(http_response_header.value) */
	test_begin("http response with NULs");
	input = i_stream_create_from_data(invalid_response_with_nuls,
					  sizeof(invalid_response_with_nuls)-1);
	parser = http_response_parser_init(input);
	while ((ret=http_response_parse_next(parser, FALSE, &response, &error)) > 0);
	test_assert(ret < 0);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_http_response_parse_valid,
		test_http_response_parse_invalid,
		NULL
	};
	return test_run(test_functions);
}
