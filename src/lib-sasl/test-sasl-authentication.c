/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "str.h"
#include "base64.h"
#include "randgen.h"
#include "test-common.h"
#include "password-scheme.h"
#include "sasl-server.h"
#include "sasl-server-oauth2.h"
#include "dsasl-client.h"
#include "dsasl-client-mech-ntlm-dummy.h"

#include <unistd.h>

struct test_sasl {
	const char *mech;

	enum sasl_server_authid_type authid_type;
	struct {
		const char *authid;
		const char *authzid;
		const char *realm;
		const char *password;
	} client, server;

	bool failure:1;
};

struct test_sasl_context {
	pool_t pool;

	struct sasl_server_req_ctx ssrctx;
	const struct test_sasl *test;

	struct dsasl_client *client;

	const char *authid;
	const char *authzid;
	const char *realm;
	const char *cbind_type;
	buffer_t *cbind_data;

	bool server_cbinding:1;
	bool auth_initial:1;
	bool out_of_band_cycle:1;
	bool finished:1;
};

struct event *test_event;

static void
test_create_channel_binding_data(struct test_sasl_context *tctx, const char *type)
{
	unsigned char cbdata[16];

	if (tctx->cbind_type != NULL) {
		test_assert_strcmp(tctx->cbind_type, type);
		i_assert(tctx->cbind_data != NULL);
	} else {
		i_assert(tctx->cbind_data == NULL);
		tctx->cbind_type = p_strdup(tctx->pool, type);
		random_fill(cbdata, sizeof(cbdata));
		tctx->cbind_data = buffer_create_dynamic(
			tctx->pool, MAX_BASE64_ENCODED_SIZE(sizeof(cbdata))+1);
		base64_encode(cbdata, sizeof(cbdata), tctx->cbind_data);
	}
}

static bool
test_server_request_set_authid(struct sasl_server_req_ctx *rctx,
			       enum sasl_server_authid_type authid_type,
			       const char *authid)
{
	struct test_sasl_context *tctx =
		container_of(rctx, struct test_sasl_context, ssrctx);
	const struct test_sasl *test = tctx->test;

	test_assert(test->authid_type == authid_type);

	if (!test->failure)
		test_assert_strcmp(test->server.authid, authid);
	tctx->authid = p_strdup(tctx->pool, authid);
	return TRUE;
}

static bool
test_server_request_set_authzid(struct sasl_server_req_ctx *rctx,
				const char *authzid)
{
	struct test_sasl_context *tctx =
		container_of(rctx, struct test_sasl_context, ssrctx);
	const struct test_sasl *test = tctx->test;

	if (test->failure)
		;
	else if (test->server.authzid == NULL || *test->server.authzid == '\0')
		test_assert_strcmp(test->server.authid, authzid);
	else
		test_assert_strcmp(test->server.authzid, authzid);
	tctx->authzid = p_strdup(tctx->pool, authzid);
	return TRUE;
}

static void
test_server_request_set_realm(struct sasl_server_req_ctx *rctx,
			      const char *realm)
{
	struct test_sasl_context *tctx =
		container_of(rctx, struct test_sasl_context, ssrctx);
	const struct test_sasl *test = tctx->test;

	if (!test->failure)
		test_assert_strcmp(test->server.realm, realm);
	tctx->realm = p_strdup(tctx->pool, realm);
}

static bool
test_server_request_get_extra_field(struct sasl_server_req_ctx *rctx ATTR_UNUSED,
				    const char *name ATTR_UNUSED,
				    const char **field_r)
{
	/* No extra fields tested yet */
	*field_r = NULL;
	return FALSE;
}

static void
test_server_request_start_channel_binding(struct sasl_server_req_ctx *rctx,
					  const char *type)
{
	struct test_sasl_context *tctx =
		container_of(rctx, struct test_sasl_context, ssrctx);

	test_create_channel_binding_data(tctx, type);
	tctx->server_cbinding = TRUE;
}

static int
test_server_request_accept_channel_binding(struct sasl_server_req_ctx *rctx,
					   buffer_t **data_r)
{
	struct test_sasl_context *tctx =
		container_of(rctx, struct test_sasl_context, ssrctx);

	if (!tctx->server_cbinding)
		return -1;

	*data_r = tctx->cbind_data;
	return 0;
}

static void
test_server_request_verify_plain(struct sasl_server_req_ctx *rctx,
				 const char *password,
				 sasl_server_passdb_callback_t *callback)
{
	struct test_sasl_context *tctx =
		container_of(rctx, struct test_sasl_context, ssrctx);
	const struct test_sasl *test = tctx->test;
	struct sasl_passdb_result result;

	i_zero(&result);

	if (null_strcmp(test->server.authid, tctx->authid) != 0 ||
	    null_strcmp(test->server.authzid, tctx->authzid) != 0) {
		e_debug(test_event, "User unknown");
		result.status = SASL_PASSDB_RESULT_USER_UNKNOWN;
		callback(&tctx->ssrctx, &result);
		return;
	}

	if (strcmp(test->server.password, password) != 0) {
		e_debug(test_event, "Password mismatch");
		result.status = SASL_PASSDB_RESULT_PASSWORD_MISMATCH;
		callback(&tctx->ssrctx, &result);
		return ;
	}

	result.status = SASL_PASSDB_RESULT_OK;
	callback(&tctx->ssrctx, &result);
}

static void
test_server_request_lookup_credentials(
	struct sasl_server_req_ctx *rctx, const char *scheme,
	sasl_server_passdb_callback_t *callback)
{
	struct test_sasl_context *tctx =
		container_of(rctx, struct test_sasl_context, ssrctx);
	const struct test_sasl *test = tctx->test;
	struct sasl_passdb_result result;

	i_zero(&result);

	if (null_strcmp(test->server.authid, tctx->authid) != 0 ||
	    null_strcmp(test->server.authzid, tctx->authzid) != 0) {
		e_debug(test_event, "User unknown");
		result.status = SASL_PASSDB_RESULT_USER_UNKNOWN;
		callback(&tctx->ssrctx, &result);
		return;
	}

	const struct password_generate_params params = {
		.user = (test->server.realm == NULL ? test->server.authid :
			 t_strconcat(test->server.authid, "@",
				     test->server.realm, NULL)),
	};

	if (!password_generate(test->server.password, &params, scheme,
			       &result.credentials.data,
			       &result.credentials.size)) {
		result.status = SASL_PASSDB_RESULT_INTERNAL_FAILURE;
		callback(&tctx->ssrctx, &result);
		return;
	}

	result.status = SASL_PASSDB_RESULT_OK;
	callback(&tctx->ssrctx, &result);
}

static void
test_server_request_output(struct sasl_server_req_ctx *rctx,
			   const struct sasl_server_output *output)
{
	struct test_sasl_context *tctx =
		container_of(rctx, struct test_sasl_context, ssrctx);
	const struct test_sasl *test = tctx->test;
	bool failed = FALSE, expected = FALSE;

	switch (output->status) {
	case SASL_SERVER_OUTPUT_INTERNAL_FAILURE:
		e_debug(test_event, "Internal failure");
		failed = TRUE;
		test_assert(FALSE);
		tctx->finished = TRUE;
		break;
	case SASL_SERVER_OUTPUT_PASSWORD_MISMATCH:
		e_debug(test_event, "Password mismatch");
		/* Fall through */
	case SASL_SERVER_OUTPUT_FAILURE:
		failed = TRUE;
		expected = test->failure;
		tctx->finished = TRUE;
		break;
	case SASL_SERVER_OUTPUT_SUCCESS:
		expected = !test->failure;
		tctx->finished = TRUE;
		break;
	case SASL_SERVER_OUTPUT_CONTINUE:
		expected = TRUE;
		break;
	}

	test_out_quiet("server input/output", expected);

	if (failed || test_has_failed())
		;
	else if (output->data_size == 0 && output->data == NULL)
		tctx->out_of_band_cycle = TRUE;
	else if (output->data_size > 0) {
		enum dsasl_client_result result;
		const char *error = NULL;

		result = dsasl_client_input(tctx->client,
					    output->data, output->data_size,
					    &error);
		test_out_reason_quiet("client input",
				      result == DSASL_CLIENT_RESULT_OK, error);
	}
}

static int
test_server_oauth2_auth_new(struct sasl_server_req_ctx *rctx,
			    pool_t pool ATTR_UNUSED, const char *token,
			    struct sasl_server_oauth2_request **req_r)
{
	struct test_sasl_context *tctx =
		container_of(rctx, struct test_sasl_context, ssrctx);
	const struct test_sasl *test = tctx->test;

	*req_r = NULL;

	if (null_strcmp(test->server.authid, tctx->authid) != 0 ||
	    null_strcmp(test->server.authzid, tctx->authzid) != 0 ||
	    strcmp(test->server.password, token) != 0) {
		const struct sasl_server_oauth2_failure failure = {
			.status = "invalid_token",
		};
		sasl_server_oauth2_request_fail(rctx, &failure);
		return -1;
	}

	sasl_server_oauth2_request_succeed(rctx);
	return 0;
}

struct sasl_server_oauth2_funcs server_oauth2_funcs = {
	.auth_new = test_server_oauth2_auth_new,
};

struct sasl_server_request_funcs server_funcs = {
	.request_set_authid = test_server_request_set_authid,
	.request_set_authzid = test_server_request_set_authzid,
	.request_set_realm = test_server_request_set_realm,

	.request_get_extra_field = test_server_request_get_extra_field,

	.request_start_channel_binding =
		test_server_request_start_channel_binding,
	.request_accept_channel_binding =
		test_server_request_accept_channel_binding,

	.request_verify_plain = test_server_request_verify_plain,
	.request_lookup_credentials = test_server_request_lookup_credentials,

	.request_output = test_server_request_output,
};

static int
test_client_channel_binding_callback(const char *type, void *context,
				     const buffer_t **data_r,
				     const char **error_r)
{
	struct test_sasl_context *tctx = context;

	*error_r = NULL;

	test_create_channel_binding_data(tctx, type);
	*data_r = tctx->cbind_data;
	return 0;
}

static void test_sasl_interact(struct test_sasl_context *tctx)
{
	const unsigned char *sasl_data = NULL;
	size_t sasl_data_size = 0;
	const char *error = NULL;
	enum dsasl_client_result result;

	if (tctx->auth_initial) {
		result = dsasl_client_output(tctx->client,
					     &sasl_data, &sasl_data_size,
					     &error);
		test_out_reason_quiet("client initial",
				      result == DSASL_CLIENT_RESULT_OK, error);
		if (test_has_failed())
			return;
	}
	sasl_server_request_initial(&tctx->ssrctx,
				    sasl_data, sasl_data_size);

	while (!test_has_failed() && !tctx->finished) {
		sasl_data = NULL;
		sasl_data_size = 0;

		if (!tctx->out_of_band_cycle) {
			result = dsasl_client_output(tctx->client,
						     &sasl_data, &sasl_data_size,
						     &error);
			test_out_reason_quiet("client output",
					      result == DSASL_CLIENT_RESULT_OK,
					      error);
		}

		sasl_server_request_input(&tctx->ssrctx,
					  sasl_data, sasl_data_size);
	}
}

static void
test_sasl_run_once(const struct test_sasl *test,
		   const struct sasl_server_mech *server_mech,
		   bool auth_initial)
{
	const struct dsasl_client_mech *client_mech;
	struct test_sasl_context tctx;

	i_zero(&tctx);
	tctx.pool = pool_alloconly_create(MEMPOOL_GROWING"test_sasl", 2048);
	tctx.test = test;
	tctx.auth_initial = auth_initial;

	sasl_server_request_create(&tctx.ssrctx, server_mech, "imap", NULL);

	const char *authid = (test->client.authid != NULL ?
			      test->client.authid : test->server.authid);
	const char *authzid = (test->client.authzid != NULL ?
			       test->client.authzid : test->server.authzid);
	const char *realm = (test->client.realm != NULL ?
			     test->client.realm : test->server.realm);
	const char *password = (test->client.password != NULL ?
				test->client.password :
				test->server.password);

	struct dsasl_client_settings client_set = {
		.authid = (realm == NULL ? authid :
			   t_strconcat(authid, "@", realm, NULL)),
		.authzid = authzid,
		.password = password,
		.protocol = "imap",
		.host = "example.com",
	};
	client_mech = dsasl_client_mech_find(test->mech);
	i_assert(client_mech != NULL);
	tctx.client = dsasl_client_new(client_mech, &client_set);
	i_assert(tctx.client != NULL);

	dsasl_client_enable_channel_binding(
		tctx.client, SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_3,
		test_client_channel_binding_callback, &tctx);

	test_sasl_interact(&tctx);

	dsasl_client_free(&tctx.client);
	sasl_server_request_destroy(&tctx.ssrctx);

	pool_unref(&tctx.pool);
}

static void
test_sasl_run(const struct test_sasl *test, const char *label,
	      bool auth_initial)
{
	const char *server_realms[3];
	struct sasl_server *server;
	struct sasl_server_instance *server_inst;
	unsigned int i;

	i = 0;
	if (test->server.realm != NULL)
		server_realms[i++] = test->server.realm;
	if (test->client.realm != NULL &&
	    null_strcasecmp(test->client.realm, test->server.realm) != 0)
		server_realms[i++] = test->client.realm;
	server_realms[i] = NULL;

	test_begin(t_strdup_printf("sasl %s %s%s",
				   label, test->mech,
				   (auth_initial ? " (initial)" : "")));

	const struct sasl_server_settings server_set = {
		.realms = server_realms,
		.event_parent = test_event,
	};
	server = sasl_server_init(test_event, &server_funcs);
	server_inst = sasl_server_instance_create(server, &server_set);

	sasl_server_mech_register_anonymous(server_inst);
	sasl_server_mech_register_cram_md5(server_inst);
	sasl_server_mech_register_digest_md5(server_inst);
	sasl_server_mech_register_external(server_inst);
	sasl_server_mech_register_login(server_inst);
	sasl_server_mech_register_plain(server_inst);
	sasl_server_mech_register_scram_sha1(server_inst);
	sasl_server_mech_register_scram_sha1_plus(server_inst);
	sasl_server_mech_register_scram_sha256(server_inst);
	sasl_server_mech_register_scram_sha256_plus(server_inst);

	sasl_server_mech_register_oauthbearer(server_inst, &server_oauth2_funcs,
					      NULL);
	sasl_server_mech_register_xoauth2(server_inst, &server_oauth2_funcs,
					  NULL);

	struct sasl_server_winbind_settings winbind_set = {
		.helper_path = TEST_WINBIND_HELPER_PATH,
	};
	sasl_server_mech_register_winbind_ntlm(server_inst, &winbind_set);

	const struct sasl_server_mech *server_mech;

	server_mech = sasl_server_mech_find(server_inst, test->mech);
	i_assert(server_mech != NULL);

	test_sasl_run_once(test, server_mech, auth_initial);

	sasl_server_instance_unref(&server_inst);
	sasl_server_deinit(&server);
	test_end();
}

/*
 * Successful authentication
 */

static const struct test_sasl success_tests[] = {
	/* PLAIN */
	{
		.mech = "PLAIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
	},
	{
		.mech = "PLAIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
	},
	/* LOGIN */
	{
		.mech = "LOGIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
	},
	/* CRAM-MD5 */
	{
		.mech = "CRAM-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
	},
	/* DIGEST-MD5 */
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.realm = "example.org",
			.password = "pass",
		},
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.realm = "example.org",
			.password = "pass",
		},
	},
	/* SCRAM-SHA-1 */
	{
		.mech = "SCRAM-SHA-1",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
	},
	{
		.mech = "SCRAM-SHA-1",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
	},
	/* SCRAM-SHA-256 */
	{
		.mech = "SCRAM-SHA-256",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
	},
	{
		.mech = "SCRAM-SHA-256",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
	},
	/* SCRAM-SHA-1-PLUS */
	{
		.mech = "SCRAM-SHA-1-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
	},
	{
		.mech = "SCRAM-SHA-1-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
	},
	/* SCRAM-SHA-256-PLUS */
	{
		.mech = "SCRAM-SHA-256-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
	},
	{
		.mech = "SCRAM-SHA-256-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
	},
	/* OAUTHBEARER */
	{
		.mech = "OAUTHBEARER",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "tokentokentoken",
		},
	},
	/* EXTERNAL */
	{
		.mech = "EXTERNAL",
		.authid_type = SASL_SERVER_AUTHID_TYPE_EXTERNAL,
		.server = {
			.authid = "",
			.authzid = "user",
			.password = "",
		},
	},
	/* ANONYMOUS */
	{
		.mech = "ANONYMOUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_ANONYMOUS,
		.server = {
			.authid = "",
			.authzid = "",
			.password = "",
		},
	},
	/* NTLM */
	{
		.mech = "NTLM",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user@EXAMPLE.COM",
			.authzid = "",
			.password = "",
		},
	},
	/* XOAUTH2 */
	{
		.mech = "XOAUTH2",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "tokentokentoken",
		},
	},
};

static const unsigned int success_tests_count = N_ELEMENTS(success_tests);

static void test_sasl_success(void)
{
	unsigned int i;

	for (i = 0; i < success_tests_count; i++) {
		const struct test_sasl *test = &success_tests[i];

		test_sasl_run(test, "success", FALSE);
		test_sasl_run(test, "success", TRUE);
	}
}

/*
 * Bad credentials
 */

static const struct test_sasl bad_creds_tests[] = {
	/* PLAIN */
	{
		.mech = "PLAIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "PLAIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	{
		.mech = "PLAIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "master",
			.authzid = "user",
		},
		.failure = TRUE,
	},
	{
		.mech = "PLAIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "commander",
		},
		.failure = TRUE,
	},
	{
		.mech = "PLAIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authzid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "PLAIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	/* LOGIN */
	{
		.mech = "LOGIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "LOGIN",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.password= "florp",
		},
		.failure = TRUE,
	},
	/* CRAM-MD5 */
	{
		.mech = "CRAM-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "CRAM-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.password= "florp",
		},
		.failure = TRUE,
	},
	/* DIGEST-MD5 */
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.password= "florp",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "master",
			.authzid = "user",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "commander",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authzid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.realm = "example.org",
			.password = "pass",
		},
		.client = {
			.authid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.realm = "example.org",
			.password = "pass",
		},
		.client = {
			.realm = "example.com",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.realm = "example.org",
			.password = "pass",
		},
		.client = {
			.password= "florp",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.realm = "example.org",
			.password = "pass",
		},
		.client = {
			.authid = "master",
			.authzid = "user",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.realm = "example.org",
			.password = "pass",
		},
		.client = {
			.authid = "commander",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.realm = "example.org",
			.password = "pass",
		},
		.client = {
			.authzid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.realm = "example.org",
			.password = "pass",
		},
		.client = {
			.realm = "example.com",
		},
		.failure = TRUE,
	},
	{
		.mech = "DIGEST-MD5",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.realm = "example.org",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	/* SCRAM-SHA-1 */
	{
		.mech = "SCRAM-SHA-1",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "master",
			.authzid = "user",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "commander",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authzid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	/* SCRAM-SHA-256 */
	{
		.mech = "SCRAM-SHA-256",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "master",
			.authzid = "user",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "commander",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authzid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	/* SCRAM-SHA-1-PLUS */
	{
		.mech = "SCRAM-SHA-1-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "master",
			.authzid = "user",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "commander",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authzid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-1-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	/* SCRAM-SHA-256-PLUS */
	{
		.mech = "SCRAM-SHA-256-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "master",
			.authzid = "user",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authid = "commander",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.authzid = "userb",
		},
		.failure = TRUE,
	},
	{
		.mech = "SCRAM-SHA-256-PLUS",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "master",
			.authzid = "user",
			.password = "pass",
		},
		.client = {
			.password = "florp",
		},
		.failure = TRUE,
	},
	/* OAUTHBEARER */
	{
		.mech = "OAUTHBEARER",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "tokentokentoken",
		},
		.client = {
			.authid = "userb",
		},		
		.failure = TRUE,
	},
	{
		.mech = "OAUTHBEARER",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "tokentokentoken",
		},
		.client = {
			.password = "noketnoketnoket",
		},
		.failure = TRUE,
	},
	/* EXTERNAL */
	{
		.mech = "EXTERNAL",
		.authid_type = SASL_SERVER_AUTHID_TYPE_EXTERNAL,
		.server = {
			.authid = "",
			.authzid = "user",
			.password = "",
		},
		.client = {
			.authzid = "userb",
		},
		.failure = TRUE,
	},
	/* NTLM */
	{
		.mech = "NTLM",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user@EXAMPLE.COM",
			.authzid = "",
			.password = "",
		},
		.client = {
			.authid = "userb@EXAMPLE.COM",
		},
		.failure = TRUE,
	},
	/* XOAUTH2 */
	{
		.mech = "XOAUTH2",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "tokentokentoken",
		},
		.client = {
			.authid = "userb",
		},		
		.failure = TRUE,
	},
	{
		.mech = "XOAUTH2",
		.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME,
		.server = {
			.authid = "user",
			.password = "tokentokentoken",
		},
		.client = {
			.password = "noketnoketnoket",
		},
		.failure = TRUE,
	},
};

static const unsigned int bad_creds_tests_count = N_ELEMENTS(bad_creds_tests);

static void test_sasl_bad_credentials(void)
{
	unsigned int i;

	for (i = 0; i < bad_creds_tests_count; i++) {
		const struct test_sasl *test = &bad_creds_tests[i];

		test_sasl_run(test, "bad credentials", FALSE);
	}
}

int main(int argc, char *argv[])
{
	static void (*const test_functions[])(void) = {
		test_sasl_success,
		test_sasl_bad_credentials,
		NULL
	};
	bool debug = FALSE;
	int ret, c;

	lib_init();
	lib_signals_init();

	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	test_event = event_create(NULL);
	event_set_forced_debug(test_event, debug);
	password_schemes_init();
	dsasl_clients_init();
	dsasl_client_mech_ntlm_init_dummy();

	ret = test_run(test_functions);

	dsasl_clients_deinit();
	password_schemes_deinit();
	event_unref(&test_event);
	lib_signals_deinit();
	lib_deinit();
	return ret;
}
