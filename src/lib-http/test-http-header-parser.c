/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "test-common.h"
#include "http-header-parser.h"

#include <time.h>

struct http_header_parse_result {
	const char *name;
	const char *value;
};

struct http_header_parse_test {
	const char *header;
	const struct http_header_parse_result *fields;
};

/* Valid header tests */

static struct http_header_parse_result valid_header_parse_result1[] = {
	{ "Date", "Sat, 06 Oct 2012 16:01:44 GMT" },
	{ "Server", "Apache/2.2.16 (Debian)" },
	{ "Last-Modified", "Mon, 30 Jul 2012 11:09:28 GMT" },
	{ "Etag", "\"3d24677-3261-4c60a1863aa00\"" },
	{ "Accept-Ranges", "bytes" },
	{ "Vary", "Accept-Encoding" },
	{ "Content-Encoding", "gzip" },
	{ "Content-Length", "4092" },
	{ "Keep-Alive", "timeout=15, max=100" },
	{ "Connection", "Keep-Alive" },
	{ "Content-Type", "text/html" },
	{ NULL, NULL }
};

static struct http_header_parse_result valid_header_parse_result2[] = {
	{ "Host", "p5-lrqzb4yavu4l7nagydw-428649-i2-v6exp3-ds.metric.example.com" },
	{ "User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0)" },
	{ "Accept", "image/png,image/*;q=0.8,*/*;q=0.5" },
	{ "Accept-Language", "en-us,en;q=0.5" },
	{ "Accept-Encoding", "gzip, deflate" },
	{ "DNT", "1" },
	{ "Connection", "keep-alive" },
	{ "Referer", "http://www.example.nl/" },
	{ NULL, NULL }
};

static struct http_header_parse_result valid_header_parse_result3[] = {
	{ "Date", "Sat, 06 Oct 2012 17:12:37 GMT" },
	{ "Server", "Apache/2.2.16 (Debian) PHP/5.3.3-7+squeeze14 with"
		" Suhosin-Patch proxy_html/3.0.1 mod_python/3.3.1 Python/2.6.6"
		" mod_ssl/2.2.16 OpenSSL/0.9.8o mod_perl/2.0.4 Perl/v5.10.1" },
	{ "WWW-Authenticate", "Basic realm=\"Munin\"" },
	{ "Vary", "Accept-Encoding" },
	{ "Content-Encoding", "gzip" },
	{ "Content-Length", "445" },
	{ "Keep-Alive", "timeout=15, max=98" },
	{ "Connection", "Keep-Alive" },
	{ "Content-Type", "text/html; charset=iso-8859-1" },
	{ NULL, NULL }
};

static struct http_header_parse_result valid_header_parse_result4[] = {
	{ "Age", "58" },
	{ "Date", "Sun, 04 Aug 2013 09:33:09 GMT" },
	{ "Expires", "Sun, 04 Aug 2013 09:34:08 GMT" },
	{ "Cache-Control", "max-age=60" },
	{ "Content-Length", "17336" },
	{ "Connection", "Keep-Alive" },
	{ "Via", "NS-CACHE-9.3" },
	{ "Server", "Apache" },
	{ "Vary", "Host" },
	{ "Last-Modified", "Sun, 04 Aug 2013 09:33:07 GMT" },
	{ "Content-Type", "text/html; charset=utf-8" },
	{ "Content-Encoding", "gzip" },
	{ NULL, NULL }
};

static struct http_header_parse_result valid_header_parse_result5[] = {
	{ NULL, NULL }
};

static const struct http_header_parse_test valid_header_parse_tests[] = {
	{ .header = 
			"Date: Sat, 06 Oct 2012 16:01:44 GMT\r\n"
			"Server: Apache/2.2.16 (Debian)\r\n"
			"Last-Modified: Mon, 30 Jul 2012 11:09:28 GMT\r\n"
			"Etag: \"3d24677-3261-4c60a1863aa00\"\r\n"
			"Accept-Ranges: bytes\r\n"
			"Vary: Accept-Encoding\r\n"
			"Content-Encoding: gzip\r\n"
			"Content-Length: 4092\r\n"
			"Keep-Alive: timeout=15, max=100\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Type: text/html\r\n"
			"\r\n",
		.fields = valid_header_parse_result1
	},{
		.header =
			"Host: p5-lrqzb4yavu4l7nagydw-428649-i2-v6exp3-ds.metric.example.com\n"
			"User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0)\n"
			"Accept:\t\timage/png,image/*;q=0.8,*/*;q=0.5\n"
			"Accept-Language:\ten-us,en;q=0.5\n"
			"Accept-Encoding: \t\tgzip, deflate\n"
			"DNT:   1\n"
			"Connection: \t\tkeep-alive\n"
			"Referer:   http://www.example.nl/\n"
			"\n",
		.fields = valid_header_parse_result2
	},{
		.header =
			"Date: Sat, 06 Oct 2012 17:12:37 GMT\r\n"
			"Server: Apache/2.2.16 (Debian) PHP/5.3.3-7+squeeze14 with\r\n"
			" Suhosin-Patch proxy_html/3.0.1 mod_python/3.3.1 Python/2.6.6\r\n"
			" mod_ssl/2.2.16 OpenSSL/0.9.8o mod_perl/2.0.4 Perl/v5.10.1\r\n"
			"WWW-Authenticate: Basic realm=\"Munin\"\r\n"
			"Vary: Accept-Encoding\r\n"
			"Content-Encoding: gzip\r\n"
			"Content-Length: 445\r\n"
			"Keep-Alive: timeout=15, max=98\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Type: text/html; charset=iso-8859-1\r\n"
			"\r\n",
		.fields = valid_header_parse_result3
	},{
		.header = 
			"Age: 58        \r\n"
			"Date: Sun, 04 Aug 2013 09:33:09 GMT\r\n"
			"Expires: Sun, 04 Aug 2013 09:34:08 GMT\r\n"
			"Cache-Control: max-age=60        \r\n"
			"Content-Length: 17336     \r\n"
			"Connection: Keep-Alive\r\n"
			"Via: NS-CACHE-9.3\r\n"
			"Server: Apache\r\n"
			"Vary: Host\r\n"
			"Last-Modified: Sun, 04 Aug 2013 09:33:07 GMT\r\n"
			"Content-Type: text/html; charset=utf-8\r\n"
			"Content-Encoding: gzip\r\n"
			"\r\n",
		.fields = valid_header_parse_result4
	},{
		.header =
			"\r\n",
		.fields = valid_header_parse_result5
	}
};

unsigned int valid_header_parse_test_count = N_ELEMENTS(valid_header_parse_tests);

static void test_http_header_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_header_parse_test_count; i++) T_BEGIN {
		struct istream *input;
		struct http_header_parser *parser;
		const char *header, *field_name, *error;
		const unsigned char *field_data;
		size_t field_size;
		int ret;
		unsigned int j, pos, header_len;

		header = valid_header_parse_tests[i].header;
		header_len = strlen(header);
		input = test_istream_create_data(header, header_len);
		parser = http_header_parser_init(input);

		test_begin(t_strdup_printf("http header valid [%d]", i));

		j = 0; pos = 0; test_istream_set_size(input, 0);
		while ((ret=http_header_parse_next_field
			(parser, &field_name, &field_data, &field_size, &error)) >= 0) {
			const struct http_header_parse_result *result;
			const char *field_value;

			if (ret == 0) {
				if (pos == header_len)
					break;
				test_istream_set_size(input, ++pos);
				continue;
			}

			if (field_name == NULL) break;

			result = &valid_header_parse_tests[i].fields[j];
			field_value = t_strndup(field_data, field_size);

			if (result->name == NULL) {
				test_out_reason("valid", FALSE,
					t_strdup_printf("%s: %s", field_name, field_value));
				break;
			}

			test_out_reason("valid",
				strcmp(result->name, field_name) == 0 &&
				strcmp(result->value, field_value) == 0,
				t_strdup_printf("%s: %s", field_name, field_value));
			j++;
		}

		test_out("parse success", ret > 0);
		test_end();
		http_header_parser_deinit(&parser);
	} T_END;
}

static const char *invalid_header_parse_tests[] = {
	"Date: Sat, 06 Oct 2012 16:01:44 GMT\r\n"
	"Server : Apache/2.2.16 (Debian)\r\n"
	"Last-Modified: Mon, 30 Jul 2012 11:09:28 GMT\r\n"
	"\r\n",
	"Date: Sat, 06 Oct 2012 17:18:22 GMT\r\n"
	"Server: Apache/2.2.3 (CentOS)\r\n"
	"X Powered By: PHP/5.3.6\r\n"
	"\r\n",
	"Host: www.example.com\n\r"
	"Accept: image/png,image/*;q=0.8,*/*;q=0.5\n\r"
	"Accept-Language: en-us,en;q=0.5\n\r"
	"Accept-Encoding: gzip, deflate\n\r"
	"\n\r",
	"Host: p5-lrqzb4yavu4l7nagydw-428649-i2-v6exp3-ds.metric.example.com\n"
	"User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0)\n"
	"Accept:\t\timage/png,image/*;q=0.8,*/\177;q=0.5\n"
	"\n",
	"Date: Sat, 06 Oct 2012 17:12:37 GMT\r\n"
	"Server: Apache/2.2.16 (Debian) PHP/5.3.3-7+squeeze14 with\r\n"
	"Suhosin-Patch proxy_html/3.0.1 mod_python/3.3.1 Python/2.6.6\r\n"
	"mod_ssl/2.2.16 OpenSSL/0.9.8o mod_perl/2.0.4 Perl/v5.10.1\r\n"
	"\r\n",
};

unsigned int invalid_header_parse_test_count = N_ELEMENTS(invalid_header_parse_tests);

static void test_http_header_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_header_parse_test_count; i++) T_BEGIN {
		struct istream *input;
		struct http_header_parser *parser;
		const char *header, *field_name, *error;
		const unsigned char *field_data;
		size_t field_size;
		int ret;

		header = invalid_header_parse_tests[i];
		input = i_stream_create_from_data(header, strlen(header));
		parser = http_header_parser_init(input);

		test_begin(t_strdup_printf("http header invalid [%d]", i));

		while ((ret=http_header_parse_next_field
			(parser, &field_name, &field_data, &field_size, &error)) > 0) {
			if (field_name == NULL) break;
		}

		test_out("parse failure", ret < 0);
		test_end();
		http_header_parser_deinit(&parser);
	} T_END;
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_http_header_parse_valid,
		test_http_header_parse_invalid,
		NULL
	};
	return test_run(test_functions);
}
