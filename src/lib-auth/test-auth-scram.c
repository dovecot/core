/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "hmac.h"
#include "randgen.h"
#include "hash-method.h"
#include "sha1.h"
#include "sha2.h"
#include "base64.h"
#include "auth-scram-server.h"
#include "auth-scram-client.h"

struct backend_context {
	pool_t pool;

	struct auth_scram_server asserver;
	struct auth_scram_client asclient;
	unsigned int cycle;

	const char *authid;
	const char *authzid;
	const char *password;
	unsigned int iterate_count;

	const char *username;
	const char *login_username;

	enum auth_scram_server_error expect_error;
	unsigned int test_id;
};

static bool
test_auth_set_username(struct auth_scram_server *asserver, const char *username,
		       const char **error_r)
{
	struct backend_context *bctx =
		container_of(asserver, struct backend_context, asserver);

	if (bctx->expect_error == AUTH_SCRAM_SERVER_ERROR_BAD_USERNAME) {
		*error_r = "Bad username";
		return FALSE;
	}

	bctx->username = p_strdup(bctx->pool, username);
	*error_r = NULL;
	return TRUE;
}

static bool
test_auth_set_login_username(struct auth_scram_server *asserver,
			     const char *username, const char **error_r)
{
	struct backend_context *bctx =
		container_of(asserver, struct backend_context, asserver);

	if (bctx->expect_error == AUTH_SCRAM_SERVER_ERROR_BAD_LOGIN_USERNAME) {
		*error_r = "Bad login username";
		return FALSE;
	}

	bctx->login_username = p_strdup(bctx->pool, username);
	*error_r = NULL;
	return TRUE;
}

static int
test_auth_credentials_lookup(struct auth_scram_server *asserver,
			     struct auth_scram_key_data *key_data)
{
	struct backend_context *bctx =
		container_of(asserver, struct backend_context, asserver);

	if (bctx->expect_error == AUTH_SCRAM_SERVER_ERROR_LOOKUP_FAILED)
		return -1;

	auth_scram_generate_key_data(key_data->hmethod, bctx->password,
				     bctx->iterate_count, &key_data->iter_count,
				     &key_data->salt, key_data->stored_key,
				     key_data->server_key);

	return 1;
}

static const struct auth_scram_server_backend backend = {
	.set_username = test_auth_set_username,
	.set_login_username = test_auth_set_login_username,
	.credentials_lookup = test_auth_credentials_lookup,
};

static int
test_auth_client_input(struct backend_context *bctx,
		       const unsigned char *input, size_t input_len,
		       const char **error_r)
{
	return auth_scram_client_input(&bctx->asclient, input, input_len,
				       error_r);
}

static void
test_auth_client_output(struct backend_context *bctx,
			const unsigned char **output_r, size_t *output_len_r)
{
	const char *output;
	const char *const *parts;

	if (bctx->expect_error != AUTH_SCRAM_SERVER_ERROR_PROTOCOL_VIOLATION) {
		auth_scram_client_output(&bctx->asclient, output_r,
					 output_len_r);
		return;
	}

	if (bctx->cycle == 0) {
		switch (bctx->test_id) {
		case 0:
			output = "";
			break;
		case 1:
			output = ",";
			break;
		case 2:
			output = ",,";
			break;
		case 3:
			output = ",,,";
			break;
		case 4:
			output = "p=AAAAAA,,,";
			break;
		case 5:
			output = "y,t=frop,,";
			break;
		case 6:
			output = "y,a=frml=FFrop,,";
			break;
		case 7:
			output = "y,,m=frop,";
			break;
		case 8:
			output = "y,,nn,";
			break;
		case 9:
			output = "y,,n=frml=FFrop,";
			break;
		case 10:
			output = "y,,n=user,q=frop";
			break;
		default:
			auth_scram_client_output(&bctx->asclient, output_r,
						 output_len_r);
			return;
		}
	} else {
		auth_scram_client_output(&bctx->asclient, output_r,
					 output_len_r);
		parts = t_strsplit(t_strndup(*output_r, *output_len_r), ",");
		i_assert(parts[0] != NULL);
		i_assert(parts[1] != NULL);
		i_assert(parts[2] != NULL);

		switch (bctx->test_id) {
		case 11:
			output = "";
			break;
		case 12:
			output = ",";
			break;
		case 13:
			output = ",,";
			break;
		case 14:
			output = "t=frop,,";
			break;
		case 15:
			output = "c=bliep,,";
			break;
		case 16:
			output = t_strconcat(parts[0], ",", parts[1], "bla,",
					     parts[2], NULL);
			break;
		case 17:
			output = t_strconcat(parts[0], ",", parts[1], ",",
					     "p=f-r-o-p", NULL);
			break;
		case 18:
			output = t_strconcat(parts[0], ",", parts[1], ",",
					     "p=ZnJvcA==", NULL);
			break;
		case 19:
			output = t_strconcat(parts[0], ",", parts[1], ",",
					     "q=frop",
					     NULL);
			break;
		default:
			return;
		}
	}

	*output_r = (const unsigned char *)output;
	*output_len_r = strlen(output);
}

/*
 * Success
 */

static void
test_auth_success_one(const struct hash_method *hmethod, const char *authid,
		      const char *authzid, const char *password)
{
	struct backend_context *bctx;
	pool_t pool;
	int ret;

	pool = pool_alloconly_create_clean(
		MEMPOOL_GROWING"auth_scram_client", 1024);

	bctx = p_new(pool, struct backend_context, 1);
	bctx->pool = pool;
	bctx->authid = authid;
	bctx->authzid = authzid;
	bctx->password = password;
	bctx->iterate_count = 4096;

	auth_scram_client_init(&bctx->asclient, pool, hmethod,
			       authid, authzid, password);
	auth_scram_server_init(&bctx->asserver, pool, hmethod, &backend);

	while (!test_has_failed()) {
		const unsigned char *data;
		size_t data_size;
		enum auth_scram_server_error error_code;
		const char *error;
		bool server_end = FALSE;

		test_auth_client_output(bctx, &data, &data_size);
		ret = auth_scram_server_input(&bctx->asserver, data, data_size,
					      &error_code, &error);
		test_out_reason(t_strdup_printf("server input success (C=%u)",
						bctx->cycle),
				ret >= 0, error);
		if (ret < 0 || test_has_failed())
			break;

		server_end = auth_scram_server_output(&bctx->asserver,
						      &data, &data_size);
		ret = test_auth_client_input(bctx, data, data_size, &error);
		test_out_reason(t_strdup_printf("client input success (C=%u)",
						bctx->cycle),
				ret >= 0, error);
		if (ret < 0 || test_has_failed())
			break;

		if (server_end)
			break;
		bctx->cycle++;
	}

	auth_scram_server_deinit(&bctx->asserver);
	auth_scram_client_deinit(&bctx->asclient);

	pool_unref(&pool);
}

static void test_auth_success(void)
{
	test_begin("auth success sha1");
	test_auth_success_one(&hash_method_sha1, "user", NULL, "frop");
	test_end();

	test_begin("auth success sha1 master");
	test_auth_success_one(&hash_method_sha1, "master", "user", "frop");
	test_end();

	test_begin("auth success sha256");
	test_auth_success_one(&hash_method_sha256, "user", NULL, "frop");
	test_end();

	test_begin("auth success sha256 master");
	test_auth_success_one(&hash_method_sha256, "master", "user", "frop");
	test_end();

	test_begin("auth success sha1 ','");
	test_auth_success_one(&hash_method_sha1, "u,er", NULL, "frop");
	test_end();

	test_begin("auth success sha1 master ','");
	test_auth_success_one(&hash_method_sha1, "m,ster", ",ser", "frop");
	test_end();

	test_begin("auth success sha1 '='");
	test_auth_success_one(&hash_method_sha1, "u=er", NULL, "frop");
	test_end();

	test_begin("auth success sha1 master '='");
	test_auth_success_one(&hash_method_sha1, "m=ster", "=ser", "frop");
	test_end();
}

/*
 * Server error (client's fault)
 */

static void
test_auth_server_error_one(const struct hash_method *hmethod,
			   enum auth_scram_server_error expect_error,
			   unsigned int test_id)
{
	struct backend_context *bctx;
	const char *authid, *authzid, *server_password, *client_password;
	pool_t pool;
	int ret;

	if (expect_error == AUTH_SCRAM_SERVER_ERROR_BAD_LOGIN_USERNAME) {
		authid = "master";
		authzid = "user";
	} else {
		authid = "user";
		authzid = NULL;
	}
	if (expect_error == AUTH_SCRAM_SERVER_ERROR_VERIFICATION_FAILED) {
		client_password = "frop";
		server_password = "porf";
	} else {
		client_password = "frop";
		server_password = "frop";
	}

	pool = pool_alloconly_create_clean(
		MEMPOOL_GROWING"auth_scram_client", 1024);

	bctx = p_new(pool, struct backend_context, 1);
	bctx->pool = pool;
	bctx->authid = authid;
	bctx->authzid = authzid;
	bctx->password = server_password;
	bctx->iterate_count = 4096;
	bctx->expect_error = expect_error;
	bctx->test_id = test_id;

	auth_scram_client_init(&bctx->asclient, pool, hmethod,
			       authid, authzid, client_password);
	auth_scram_server_init(&bctx->asserver, pool, hmethod, &backend);

	while (!test_has_failed()) {
		const unsigned char *data;
		size_t data_size;
		enum auth_scram_server_error error_code;
		const char *error;
		bool server_end = FALSE;

		test_auth_client_output(bctx, &data, &data_size);
		ret = auth_scram_server_input(&bctx->asserver, data, data_size,
					      &error_code, &error);
		i_assert(ret < 0 || error_code == AUTH_SCRAM_SERVER_ERROR_NONE);
		test_out_reason(t_strdup_printf("server input error (%u)",
						bctx->cycle),
				(ret >= 0 || error_code == expect_error),
				error);
		if (ret < 0 || test_has_failed())
			break;

		server_end = auth_scram_server_output(&bctx->asserver,
						      &data, &data_size);
		ret = test_auth_client_input(bctx, data, data_size, &error);
		test_out_reason(t_strdup_printf("client input success (%u)",
						bctx->cycle),
				ret >= 0, error);
		if (ret < 0 || test_has_failed())
			break;

		if (server_end)
			break;
		bctx->cycle++;
	}

	auth_scram_server_deinit(&bctx->asserver);
	auth_scram_client_deinit(&bctx->asclient);

	pool_unref(&pool);
}

static void test_auth_server_error(void)
{
	unsigned int i;

	for (i = 0; i <= 19; i++) {
		test_begin("auth server error sha1 - protocol violation");
		test_auth_server_error_one(
			&hash_method_sha1,
			AUTH_SCRAM_SERVER_ERROR_PROTOCOL_VIOLATION, i);
		test_end();
	}

	test_begin("auth server error sha1 - bad username");
	test_auth_server_error_one(
		&hash_method_sha1,
		AUTH_SCRAM_SERVER_ERROR_BAD_USERNAME, 0);
	test_end();

	test_begin("auth server error sha256 - bad login username");
	test_auth_server_error_one(
		&hash_method_sha256,
		AUTH_SCRAM_SERVER_ERROR_BAD_LOGIN_USERNAME, 0);
	test_end();

	test_begin("auth server error sha1 - lookup failed");
	test_auth_server_error_one(
		&hash_method_sha1,
		AUTH_SCRAM_SERVER_ERROR_LOOKUP_FAILED, 0);
	test_end();

	test_begin("auth server error sha256 - lookup failed");
	test_auth_server_error_one(
		&hash_method_sha256,
		AUTH_SCRAM_SERVER_ERROR_LOOKUP_FAILED, 0);
	test_end();

	test_begin("auth server error sha1 - password mismatch");
	test_auth_server_error_one(
		&hash_method_sha1,
		AUTH_SCRAM_SERVER_ERROR_VERIFICATION_FAILED, 0);
	test_end();

	test_begin("auth server error sha256 - password mismatch");
	test_auth_server_error_one(
		&hash_method_sha256,
		AUTH_SCRAM_SERVER_ERROR_VERIFICATION_FAILED, 0);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_auth_success,
		test_auth_server_error,
		NULL
	};
	return test_run(test_functions);
}
