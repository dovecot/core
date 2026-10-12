/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "http-url.h"
#include "oauth2.h"
#include "test-common.h"

struct test_cb_ctx {
	bool called;
	char *error;
};

static void
test_cb(struct oauth2_request_result *result, struct test_cb_ctx *ctx)
{
	ctx->called = TRUE;
	ctx->error = i_strdup(result->error);
	io_loop_stop(current_ioloop);
}

static void
test_oauth2_request_wait(struct ioloop *ioloop, struct oauth2_request *req,
			 struct test_cb_ctx *ctx, const char *error)
{
	test_assert(req != NULL);

	io_loop_run(ioloop);

	test_assert(ctx->called);
	test_assert_strcmp(ctx->error, error);
	i_free(ctx->error);
}

static void test_oauth2_passwd_grant_start_empty_url(void)
{
	struct http_url empty_url;
	struct oauth2_settings set;
	struct oauth2_request_input input;
	struct test_cb_ctx ctx = { .called = FALSE, };
	struct ioloop *ioloop = io_loop_create();

	test_begin("oauth2_passwd_grant_start with unset grant_url");

	i_zero(&empty_url);
	i_zero(&set);
	set.grant_url = &empty_url;
	i_zero(&input);
	input.token = "ignored";

	struct oauth2_request *req =
		oauth2_passwd_grant_start(&set, &input, "user", "pass",
					  test_cb, &ctx);
	test_oauth2_request_wait(ioloop, req, &ctx,
				 "oauth2_grant_url must be set");

	io_loop_destroy(&ioloop);
	test_end();
}

static void test_oauth2_jwt_bearer_grant_start_empty_url(void)
{
	struct http_url empty_url;
	struct oauth2_settings set;
	struct oauth2_request_input input;
	struct test_cb_ctx ctx = { .called = FALSE, };
	struct ioloop *ioloop = io_loop_create();

	test_begin("oauth2_jwt_bearer_grant_start with unset grant_url");

	i_zero(&empty_url);
	i_zero(&set);
	set.grant_url = &empty_url;
	i_zero(&input);

	struct oauth2_request *req =
		oauth2_jwt_bearer_grant_start(&set, &input, "assertion",
					      test_cb, &ctx);
	test_oauth2_request_wait(ioloop, req, &ctx,
				 "oauth2_grant_url must be set");

	io_loop_destroy(&ioloop);
	test_end();
}

static void test_oauth2_refresh_start_empty_url(void)
{
	struct http_url empty_url;
	struct oauth2_settings set;
	struct oauth2_request_input input;
	struct test_cb_ctx ctx = { .called = FALSE, };
	struct ioloop *ioloop = io_loop_create();

	test_begin("oauth2_refresh_start with unset refresh_url");

	i_zero(&empty_url);
	i_zero(&set);
	set.refresh_url = &empty_url;
	i_zero(&input);
	input.token = "ignored";

	struct oauth2_request *req =
		oauth2_refresh_start(&set, &input, test_cb, &ctx);
	test_oauth2_request_wait(ioloop, req, &ctx,
				 "oauth2_refresh_url must be set");

	io_loop_destroy(&ioloop);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_oauth2_passwd_grant_start_empty_url,
		test_oauth2_jwt_bearer_grant_start_empty_url,
		test_oauth2_refresh_start_empty_url,
		NULL
	};
	return test_run(test_functions);
}
