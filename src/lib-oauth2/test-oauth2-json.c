/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "json-parser.h"
#include "oauth2.h"
#include "oauth2-private.h"
#include "test-common.h"

static void
test_oauth_json_valid_parsed(struct oauth2_request *req ATTR_UNUSED,
			    bool success, const char *error ATTR_UNUSED)
{
	test_assert(success);
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
	req->parser = json_parser_init(req->is);
	req->json_parsed_cb = test_oauth_json_valid_parsed;

	/* Parse the JSON response */
	for (pos = 0; pos <= strlen(test_input); pos +=2) {
		test_istream_set_size(req->is, pos);
		oauth2_parse_json(req);
		if (req->is == NULL)
			break;
	}

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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_oauth2_json_valid,
		NULL
	};
	return test_run(test_functions);
}
