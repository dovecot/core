/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "test-common.h"
#include "str.h"
#include "http-client-private.h"

static void
test_http_client_request_callback(const struct http_response *response ATTR_UNUSED,
				  void *context ATTR_UNUSED)
{
}

static void test_http_client_request_headers(void)
{
	struct http_client_settings set;
	struct http_client *client;
	struct http_client_request *req;

	test_begin("http client request headers");
	i_zero(&set);
	client = http_client_init(&set);
	req = http_client_request(client, "GET", "host", "target",
				  test_http_client_request_callback, NULL);

	test_assert(http_client_request_lookup_header(req, "qwe") == NULL);

	/* add the first */
	http_client_request_add_header(req, "qwe", "value1");
	test_assert_strcmp(http_client_request_lookup_header(req, "qwe"), "value1");
	test_assert_strcmp(str_c(req->headers), "qwe: value1\r\n");

	/* replace the first with the same length */
	http_client_request_add_header(req, "qwe", "234567");
	test_assert_strcmp(http_client_request_lookup_header(req, "qwe"), "234567");
	test_assert_strcmp(str_c(req->headers), "qwe: 234567\r\n");

	/* replace the first with smaller length */
	http_client_request_add_header(req, "qwe", "xyz");
	test_assert_strcmp(http_client_request_lookup_header(req, "qwe"), "xyz");
	test_assert_strcmp(str_c(req->headers), "qwe: xyz\r\n");

	/* replace the first with longer length */
	http_client_request_add_header(req, "qwe", "abcdefg");
	test_assert_strcmp(http_client_request_lookup_header(req, "qwe"), "abcdefg");
	test_assert_strcmp(str_c(req->headers), "qwe: abcdefg\r\n");

	/* add the second */
	http_client_request_add_header(req, "xyz", "1234");
	test_assert_strcmp(http_client_request_lookup_header(req, "qwe"), "abcdefg");
	test_assert_strcmp(http_client_request_lookup_header(req, "xyz"), "1234");
	test_assert_strcmp(str_c(req->headers), "qwe: abcdefg\r\nxyz: 1234\r\n");

	/* replace second */
	http_client_request_add_header(req, "xyz", "yuiop");
	test_assert_strcmp(http_client_request_lookup_header(req, "qwe"), "abcdefg");
	test_assert_strcmp(http_client_request_lookup_header(req, "xyz"), "yuiop");
	test_assert_strcmp(str_c(req->headers), "qwe: abcdefg\r\nxyz: yuiop\r\n");

	/* replace the first again */
	http_client_request_add_header(req, "qwe", "1234");
	test_assert_strcmp(http_client_request_lookup_header(req, "qwe"), "1234");
	test_assert_strcmp(http_client_request_lookup_header(req, "xyz"), "yuiop");
	test_assert_strcmp(str_c(req->headers), "qwe: 1234\r\nxyz: yuiop\r\n");

	/* remove the headers */
	http_client_request_remove_header(req, "qwe");
	test_assert(http_client_request_lookup_header(req, "qwe") == NULL);
	test_assert_strcmp(http_client_request_lookup_header(req, "xyz"), "yuiop");
	test_assert_strcmp(str_c(req->headers), "xyz: yuiop\r\n");

	http_client_request_remove_header(req, "xyz");
	test_assert(http_client_request_lookup_header(req, "qwe") == NULL);
	test_assert(http_client_request_lookup_header(req, "xyz") == NULL);
	test_assert_strcmp(str_c(req->headers), "");

	/* test _add_missing_header() */
	http_client_request_add_missing_header(req, "foo", "bar");
	test_assert_strcmp(str_c(req->headers), "foo: bar\r\n");
	http_client_request_add_missing_header(req, "foo", "123");
	test_assert_strcmp(str_c(req->headers), "foo: bar\r\n");

	http_client_request_abort(&req);
	http_client_deinit(&client);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_http_client_request_headers,
		NULL
	};
	return test_run(test_functions);
}
