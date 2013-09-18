/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"
#include "http-url.h"
#include "http-request-parser.h"

#include <time.h>

struct http_request_parse_test {
	const char *request;
	const char *method;
	const char *target_raw;
	struct http_request_target target;
	unsigned char version_major;
	unsigned char version_minor;
	uoff_t content_length;
	const char *payload;
};

/* Valid header tests */

static const struct http_request_parse_test
valid_request_parse_tests[] = {
	{ .request =
			"GET / HTTP/1.1\r\n"
			"Host: example.com\r\n"
			"\r\n",
		.method = "GET",
		.target_raw = "/",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ORIGIN
		},
		.version_major = 1, .version_minor = 1,
	},{ .request =
			"OPTIONS * HTTP/1.0\r\n"
			"Host: example.com\r\n"
			"\r\n",
		.method = "OPTIONS",
		.target_raw = "*",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ASTERISK
		},
		.version_major = 1, .version_minor = 0,
	},{ .request =
			"CONNECT example.com:443 HTTP/1.2\r\n"
			"Host: example.com:443\r\n"
			"\r\n",
		.method = "CONNECT",
		.target_raw = "example.com:443",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_AUTHORITY
		},
		.version_major = 1, .version_minor = 2,
	},{ .request =
			"GET https://www.example.com:443 HTTP/1.1\r\n"
			"Host: www.example.com:80\r\n"
			"\r\n",
		.method = "GET",
		.target_raw = "https://www.example.com:443",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE
		},
		.version_major = 1, .version_minor = 1,
	},{ .request =
			"POST http://api.example.com:8080/commit?user=dirk HTTP/1.1\r\n"
			"Host: api.example.com:8080\r\n"
			"Content-Length: 10\r\n"
			"\r\n"
			"Content!\r\n",
		.method = "POST",
		.target_raw = "http://api.example.com:8080/commit?user=dirk",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE,
		},
		.version_major = 1, .version_minor = 1,
		.payload = "Content!\r\n"
	}
};

unsigned int valid_request_parse_test_count =
	N_ELEMENTS(valid_request_parse_tests);

static const char *
_request_target_format(enum http_request_target_format target_format)
{
	switch (target_format) {
	case HTTP_REQUEST_TARGET_FORMAT_ORIGIN:
		return "origin";
	case HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE:
		return "absolute";
	case HTTP_REQUEST_TARGET_FORMAT_AUTHORITY:
		return "authority";
	case HTTP_REQUEST_TARGET_FORMAT_ASTERISK:
		return "asterisk";
	}
	return t_strdup_printf("<<UNKNOWN: %u>>", target_format);
}

static void test_http_request_parse_valid(void)
{
	unsigned int i;
	buffer_t *payload_buffer = buffer_create_dynamic(default_pool, 1024);

	for (i = 0; i < valid_request_parse_test_count; i++) T_BEGIN {
		struct istream *input;
		struct ostream *output;
		const struct http_request_parse_test *test;
		struct http_request_parser *parser;
		struct http_request request;
		enum http_request_parse_error error_code;
		const char *request_text, *payload, *error;
		unsigned int pos, request_text_len;
		int ret = 0;

		test = &valid_request_parse_tests[i];
		request_text = test->request;
		request_text_len = strlen(request_text);
		input = test_istream_create_data(request_text, request_text_len);
		parser = http_request_parser_init(input, NULL);

		test_begin(t_strdup_printf("http request valid [%d]", i));

		payload = NULL;
		for (pos = 0; pos <= request_text_len && ret == 0; pos++) {
			test_istream_set_size(input, pos);
			ret = http_request_parse_next
				(parser, FALSE, &request, &error_code, &error);
		}
		test_istream_set_size(input, request_text_len);
		while (ret > 0) {
			if (request.payload != NULL) {
				buffer_set_used_size(payload_buffer, 0);
				output = o_stream_create_buffer(payload_buffer);
				test_out("payload receive", 
					o_stream_send_istream(output, request.payload));
				o_stream_destroy(&output);
				payload = str_c(payload_buffer);
			} else {
				payload = NULL;
			}
			ret = http_request_parse_next
				(parser, FALSE, &request, &error_code, &error);
		}

		test_out_reason("parse success", ret == 0, error);
		
		if (ret == 0) {
			/* verify last request only */
			if (request.method == NULL || test->method == NULL) {
				test_out(t_strdup_printf("request->method = %s", test->method),
					request.method == test->method);
			} else {
				test_out(t_strdup_printf("request->method = %s", test->method),
					strcmp(request.method, test->method) == 0);
			}
			if (request.target_raw == NULL || test->target_raw == NULL) {
				test_out(t_strdup_printf("request->target = %s", test->target_raw),
					request.target_raw == test->target_raw);
			} else {
				test_out(t_strdup_printf("request->target = %s", test->target_raw),
					strcmp(request.target_raw, test->target_raw) == 0);
			}
			test_out(t_strdup_printf("request->target_format = %s",
					_request_target_format(test->target.format)),
					request.target.format == test->target.format);
			test_out(t_strdup_printf("request->version = %d.%d",
					test->version_major, test->version_minor),
					request.version_major == test->version_major &&
					request.version_minor == test->version_minor);
			if (payload == NULL || test->payload == NULL) {
				test_out(t_strdup_printf("request->payload = %s",
					str_sanitize(payload, 80)),
					payload == test->payload);
			} else {
				test_out(t_strdup_printf("request->payload = %s",
					str_sanitize(payload, 80)),
					strcmp(payload, test->payload) == 0);
			}
		}
		test_end();
		http_request_parser_deinit(&parser);
	} T_END;

	buffer_free(&payload_buffer);
}

static const char *invalid_request_parse_tests[] = {
	"GET: / HTTP/1.1\r\n"
	"Host: example.com\r\n"
	"\r\n",
	"GET % HTTP/1.1\r\n"
	"Host: example.com\r\n"
	"\r\n",
	"GET /frop\" HTTP/1.1\r\n"
	"Host: example.com\r\n"
	"\r\n",
	"GET / HTCPCP/1.0\r\n"
	"Host: example.com\r\n"
	"\r\n",
	"GET / HTTP/1.0.1\r\n"
	"Host: example.com\r\n"
	"\r\n",
	"GET / HTTP/1.1\r\n"
	"Host: \"example.com\r\n"
	"\r\n",
};

static unsigned char invalid_request_with_nuls[] =
	"GET / HTTP/1.1\r\n"
	"Host: example.com\r\n"
	"Null: text\0server\r\n"
	"\r\n";

unsigned int invalid_request_parse_test_count =
	N_ELEMENTS(invalid_request_parse_tests);

static void test_http_request_parse_invalid(void)
{
	struct http_request_parser *parser;
	struct http_request request;
	enum http_request_parse_error error_code;
	const char *request_text, *error;
	struct istream *input;
	int ret;
	unsigned int i;

	for (i = 0; i < invalid_request_parse_test_count; i++) T_BEGIN {
		const char *test;

		test = invalid_request_parse_tests[i];
		request_text = test;
		input = i_stream_create_from_data(request_text, strlen(request_text));
		parser = http_request_parser_init(input, NULL);

		test_begin(t_strdup_printf("http request invalid [%d]", i));

		while ((ret=http_request_parse_next
			(parser, FALSE, &request, &error_code, &error)) > 0);

		test_out_reason("parse failure", ret < 0, error);
		test_end();
		http_request_parser_deinit(&parser);
	} T_END;

	/* parse failure guarantees http_request_header.size equals
	   strlen(http_request_header.value) */
	test_begin("http request with NULs");
	input = i_stream_create_from_data(invalid_request_with_nuls,
					  sizeof(invalid_request_with_nuls)-1);
	parser = http_request_parser_init(input, 0);
	while ((ret=http_request_parse_next
		(parser, FALSE, &request, &error_code, &error)) > 0);
	test_assert(ret < 0);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_http_request_parse_valid,
		test_http_request_parse_invalid,
		NULL
	};
	return test_run(test_functions);
}
