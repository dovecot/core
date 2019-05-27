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

	/* add */
	http_client_request_add_header(req, "foo1", "value1");
	test_assert_strcmp(str_c(req->headers), "foo1: value1\r\n");

	http_client_request_add_header(req, "foo1", "value2");
	test_assert_strcmp(str_c(req->headers), "foo1: value1\r\nfoo1: value2\r\n");

	http_client_request_add_header(req, "foo2", "value3");
	test_assert_strcmp(str_c(req->headers), "foo1: value1\r\nfoo1: value2\r\nfoo2: value3\r\n");

	/* remove */
	http_client_request_remove_header(req, "foo1");
	test_assert_strcmp(str_c(req->headers), "foo1: value2\r\nfoo2: value3\r\n");

	http_client_request_remove_header(req, "foo2");
	test_assert_strcmp(str_c(req->headers), "foo1: value2\r\n");

	http_client_request_remove_header(req, "foo1");
	test_assert_strcmp(str_c(req->headers), "");

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
