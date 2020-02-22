/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "json-istream.h"
#include "oauth2.h"
#include "oauth2-private.h"
#include "test-common.h"

static bool cb_got_called = FALSE;

static void
test_oauth_json_valid_parsed(struct oauth2_request *req ATTR_UNUSED,
			     const char *error)
{
	test_assert(error == NULL);
	cb_got_called = TRUE;
}

static void test_oauth2_json_valid(void)
{
	static const char *test_input =
		"{\"access_token\":\"9a2dea3c-f8be-4271-b9c8-5b37da4f2f7e\","
		 "\"grant_type\":\"authorization_code\","
		 "\"openid\":\"\","
		 "\"scope\":[\"openid\",\"profile\",\"email\"],"
		 "\"profile\":\"\","
		 "\"realm\":\"/employees\","
		 "\"token_type\":\"Bearer\","
		 "\"expires_in\":2377,"
		 "\"client_id\":\"mosaic\","
		 "\"email\":\"\","
		 "\"extensions\":"
		 "{\"algorithm\":\"cuttlefish\","
		  "\"tentacles\":8"
		 "}"
		"}";
	static const struct oauth2_field fields[] = {
		{ .name = "access_token",
		  .value = "9a2dea3c-f8be-4271-b9c8-5b37da4f2f7e" },
		{ .name = "grant_type",
		  .value = "authorization_code" },
		{ .name = "openid",
		  .value = "" },
		{ .name = "profile",
		  .value = "" },
		{ .name = "realm",
		  .value = "/employees" },
		{ .name = "token_type",
		  .value = "Bearer" },
		{ .name = "expires_in",
		  .value = "2377" },
		{ .name = "client_id",
		  .value = "mosaic" },
		{ .name = "email",
		  .value = "" },
	};
	static const unsigned int fields_count = N_ELEMENTS(fields);
	struct oauth2_request *req;
	const struct oauth2_field *pfields;
	unsigned int count, i;
	pool_t pool;
	size_t pos;

	test_begin("oauth json skip");

	/* Create mock request */
	pool = pool_alloconly_create_clean("oauth2 json test", 1024);
	req = p_new(pool, struct oauth2_request, 1);
	req->pool = pool;
	p_array_init(&req->fields, req->pool, 1);
	req->is = test_istream_create_data(test_input, strlen(test_input));
	req->json_istream = json_istream_create_object(
		req->is, NULL, JSON_PARSER_FLAG_NUMBERS_AS_STRING);
	req->json_parsed_cb = test_oauth_json_valid_parsed;
	cb_got_called = FALSE;

	/* Parse the JSON response */
	for (pos = 0;; pos += 2) {
		test_istream_set_size(req->is, pos);
		oauth2_request_parse_json(req);
		if (pos >= strlen(test_input))
			break;
	}

	test_assert(cb_got_called);
	/* Verify the parsed fields */
	pfields = array_get(&req->fields, &count);
	test_assert(count == fields_count);
	if (count > fields_count)
		count = fields_count;
	for (i = 0; i < count; i++) {
		test_assert(strcmp(pfields[i].name, fields[i].name) == 0);
		test_assert(strcmp(pfields[i].value, fields[i].value) == 0);
	}

	/* Clean up */
	pool_unref(&req->pool);

	test_end();
}

static void
test_oauth_json_has_error(struct oauth2_request *req,
			  const char *error)
{
	const char *expected_error = req->req_context;
	test_assert(error != NULL);
	test_assert_strcmp(expected_error, error);
	cb_got_called = TRUE;
}

static void test_oauth2_json_error(void)
{
	test_begin("oauth2 json error");

	const char *test_input_1 =
"{\"error\":\"invalid_request\"}";
	const char *test_input_2 =
"{\"error\":\"invalid_request\",\"error_description\":\"Access denied\"}";

	/* Create mock request */
	pool_t pool = pool_alloconly_create_clean("oauth2 json test", 1024);
	struct oauth2_request *req = p_new(pool, struct oauth2_request, 1);
	req->pool = pool;
	p_array_init(&req->fields, req->pool, 1);
	req->is = test_istream_create_data(test_input_1, strlen(test_input_1));
	req->json_istream = json_istream_create_object(
		req->is, NULL, JSON_PARSER_FLAG_NUMBERS_AS_STRING);
	req->req_context = "invalid_request";
	req->json_parsed_cb = test_oauth_json_has_error;
	cb_got_called = FALSE;

	/* Parse the JSON response */
	for (size_t pos = 0;; pos += 2) {
		test_istream_set_size(req->is, pos);
		oauth2_request_parse_json(req);
		if (pos >= strlen(test_input_1))
			break;
	}

	test_assert(cb_got_called);
	pool_unref(&pool);

	pool = pool_alloconly_create_clean("oauth2 json test", 1024);
	req = p_new(pool, struct oauth2_request, 1);
	req->pool = pool;
	p_array_init(&req->fields, req->pool, 1);
	req->is = test_istream_create_data(test_input_2, strlen(test_input_2));
	req->json_istream = json_istream_create_object(
		req->is, NULL, JSON_PARSER_FLAG_NUMBERS_AS_STRING);
	req->req_context = "Access denied";
	req->json_parsed_cb = test_oauth_json_has_error;
	cb_got_called = FALSE;

	/* Parse the JSON response */
	for (size_t pos = 0;; pos += 2) {
		test_istream_set_size(req->is, pos);
		oauth2_request_parse_json(req);
		if (pos >= strlen(test_input_2))
			break;
	}

	test_assert(cb_got_called);
	pool_unref(&pool);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_oauth2_json_valid,
		test_oauth2_json_error,
		NULL
	};
	return test_run(test_functions);
}
