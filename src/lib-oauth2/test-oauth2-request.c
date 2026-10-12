/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "env-util.h"
#include "http-url.h"
#include "var-expand.h"
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

static void test_oauth2_tokeninfo_start_dot_token(void)
{
	struct var_expand_program *tmpl;
	struct oauth2_settings set;
	struct oauth2_request_input input;
	struct test_cb_ctx ctx = { .called = FALSE, };
	struct ioloop *ioloop = io_loop_create();
	const char *error;

	test_begin("oauth2_token_validation_start with a dot segment token");

	test_assert(var_expand_program_create(
		"http://127.0.0.1:1/%{access_token}", &tmpl, &error) == 0);
	i_zero(&set);
	set.tokeninfo_url = tmpl;
	i_zero(&input);
	input.token = "..";

	struct oauth2_request *req =
		oauth2_token_validation_start(&set, &input, test_cb, &ctx);
	test_oauth2_request_wait(ioloop, req, &ctx,
				 "oauth2_tokeninfo_url: Invalid token");

	var_expand_program_free(&tmpl);
	io_loop_destroy(&ioloop);
	test_end();
}

static void test_oauth2_introspection_start_dot_token(void)
{
	struct var_expand_program *tmpl;
	struct oauth2_settings set;
	struct oauth2_request_input input;
	struct test_cb_ctx ctx = { .called = FALSE, };
	struct ioloop *ioloop = io_loop_create();
	const char *error;

	test_begin("oauth2_introspection_start with a dot segment token");

	test_assert(var_expand_program_create(
		"http://127.0.0.1:1/%{access_token}", &tmpl, &error) == 0);
	i_zero(&set);
	set.introspection_mode = INTROSPECTION_MODE_GET;
	set.introspection_url = tmpl;
	i_zero(&input);
	input.token = ".";

	struct oauth2_request *req =
		oauth2_introspection_start(&set, &input, test_cb, &ctx);
	test_oauth2_request_wait(ioloop, req, &ctx,
				 "oauth2_introspection_url: Invalid token");

	var_expand_program_free(&tmpl);
	io_loop_destroy(&ioloop);
	test_end();
}

static void test_oauth2_tokeninfo_start_token_in_base(void)
{
	struct var_expand_program *tmpl;
	struct oauth2_settings set;
	struct oauth2_request_input input;
	struct test_cb_ctx ctx = { .called = FALSE, };
	struct ioloop *ioloop = io_loop_create();
	const char *error;

	test_begin("oauth2_token_validation_start with a variable as base URL");

	/* the expanded base URL is http: so %{access_token} would end up in
	   the host */
	env_put("OAUTH2_TEST_BASE", "http:");
	test_assert(var_expand_program_create(
		"%{env:OAUTH2_TEST_BASE|safe}//%{access_token}/", &tmpl,
		&error) == 0);
	i_zero(&set);
	set.tokeninfo_url = tmpl;
	i_zero(&input);
	input.token = "host";

	struct oauth2_request *req =
		oauth2_token_validation_start(&set, &input, test_cb, &ctx);
	test_oauth2_request_wait(ioloop, req, &ctx,
		"oauth2_tokeninfo_url: "
		"%{access_token} must be in the URL path or query");

	env_remove("OAUTH2_TEST_BASE");
	var_expand_program_free(&tmpl);
	io_loop_destroy(&ioloop);
	test_end();
}

static void test_oauth2_tokeninfo_start_empty_authority(void)
{
	static const struct {
		const char *base;
		const char *error;
	} tests[] = {
		/* http:///host has no authority, the token must not become
		   one */
		{ "http://", "oauth2_tokeninfo_url: "
		  "%{access_token} must be in the URL path or query" },
		/* userinfo without a host */
		{ "http://@", "oauth2_tokeninfo_url: "
		  "%{access_token} must be in the URL path or query" },
	};

	test_begin("oauth2_token_validation_start with an empty host");

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		struct var_expand_program *tmpl;
		struct oauth2_settings set;
		struct oauth2_request_input input;
		struct test_cb_ctx ctx = { .called = FALSE, };
		struct ioloop *ioloop = io_loop_create();
		const char *error;

		env_put("OAUTH2_TEST_BASE", tests[i].base);
		test_assert_idx(var_expand_program_create(
			"%{env:OAUTH2_TEST_BASE|safe}/%{access_token}", &tmpl,
			&error) == 0, i);
		i_zero(&set);
		set.tokeninfo_url = tmpl;
		i_zero(&input);
		input.token = "host";

		struct oauth2_request *req =
			oauth2_token_validation_start(&set, &input, test_cb,
						      &ctx);
		test_oauth2_request_wait(ioloop, req, &ctx, tests[i].error);

		env_remove("OAUTH2_TEST_BASE");
		var_expand_program_free(&tmpl);
		io_loop_destroy(&ioloop);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_oauth2_passwd_grant_start_empty_url,
		test_oauth2_jwt_bearer_grant_start_empty_url,
		test_oauth2_refresh_start_empty_url,
		test_oauth2_tokeninfo_start_dot_token,
		test_oauth2_introspection_start_dot_token,
		test_oauth2_tokeninfo_start_token_in_base,
		test_oauth2_tokeninfo_start_empty_authority,
		NULL
	};
	return test_run(test_functions);
}
