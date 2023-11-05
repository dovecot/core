/* Copyright (c) 2011-2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "sha1.h"
#include "sha2.h"
#include "auth-scram-server.h"
#include "mech.h"
#include "mech-scram.h"

/* s-nonce length */
#define SCRAM_SERVER_NONCE_LEN 64

struct scram_auth_request {
	struct auth_request auth_request;

	pool_t pool;
	const char *password_scheme;

	struct auth_scram_server scram_server;
	struct auth_scram_key_data *key_data;
};

static void
credentials_callback(enum passdb_result result,
		     const unsigned char *credentials, size_t size,
		     struct auth_request *auth_request)
{
	struct scram_auth_request *request =
		container_of(auth_request, struct scram_auth_request,
			     auth_request);
	struct auth_scram_key_data *key_data = request->key_data;
	const char *error;
	const unsigned char *output;
	size_t output_len;
	bool end;

	switch (result) {
	case PASSDB_RESULT_OK:
		if (scram_scheme_parse(key_data->hmethod,
				       request->password_scheme,
				       credentials, size,
				       &key_data->iter_count, &key_data->salt,
				       key_data->stored_key,
				       key_data->server_key,
				       &error) < 0) {
			e_info(auth_request->mech_event,
			       "%s", error);
			auth_request_fail(auth_request);
			break;
		}

		end = auth_scram_server_output(&request->scram_server,
					       &output, &output_len);
		i_assert(!end);
		auth_request_handler_reply_continue(auth_request,
						    output, output_len);
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(auth_request);
		break;
	default:
		auth_request_fail(auth_request);
		break;
	}
}

static bool
mech_scram_set_username(struct auth_scram_server *asserver,
			const char *username, const char **error_r)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct auth_request *auth_request = &request->auth_request;

	return auth_request_set_username(auth_request, username, error_r);
}

static bool
mech_scram_set_login_username(struct auth_scram_server *asserver,
			      const char *username, const char **error_r)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct auth_request *auth_request = &request->auth_request;

	return auth_request_set_login_username(auth_request, username, error_r);
}

static void
mech_scram_start_channel_binding(struct auth_scram_server *asserver,
				 const char *type)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct auth_request *auth_request = &request->auth_request;

	auth_request_start_channel_binding(auth_request, type);
}

static int
mech_scram_accept_channel_binding(struct auth_scram_server *asserver,
				  buffer_t **data_r)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct auth_request *auth_request = &request->auth_request;

	return auth_request_accept_channel_binding(auth_request, data_r);
}

static int
mech_scram_credentials_lookup(struct auth_scram_server *asserver,
			      struct auth_scram_key_data *key_data)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct auth_request *auth_request = &request->auth_request;

	request->key_data = key_data;
	auth_request_lookup_credentials(auth_request, request->password_scheme,
					credentials_callback);
	return 0;
}

static const struct auth_scram_server_backend scram_server_backend = {
	.set_username = mech_scram_set_username,
	.set_login_username = mech_scram_set_login_username,

	.start_channel_binding = mech_scram_start_channel_binding,
	.accept_channel_binding = mech_scram_accept_channel_binding,

	.credentials_lookup = mech_scram_credentials_lookup,
};

void mech_scram_auth_continue(struct auth_request *auth_request,
			      const unsigned char *input, size_t input_len)
{
	struct scram_auth_request *request =
		container_of(auth_request, struct scram_auth_request,
			     auth_request);
	enum auth_scram_server_error error_code;
	const char *error = NULL;
	const unsigned char *output;
	size_t output_len;
	int ret;

	ret = auth_scram_server_input(&request->scram_server, input, input_len,
				      &error_code, &error);
	if (ret < 0) {
		i_assert(error != NULL);
		if (error_code == AUTH_SCRAM_SERVER_ERROR_VERIFICATION_FAILED) {
			e_info(auth_request->mech_event,
			       AUTH_LOG_MSG_PASSWORD_MISMATCH);
		} else {
			e_info(auth_request->mech_event, "%s", error);
		}
		auth_request_fail(auth_request);
		return;
	}
	if (ret == 0)
		return;

	if (!auth_scram_server_output(&request->scram_server,
				      &output, &output_len)) {
		auth_request_handler_reply_continue(auth_request,
						    output, output_len);
		return;
	}

	auth_request_success(auth_request, output, output_len);
}

struct auth_request *
mech_scram_auth_new(const struct hash_method *hash_method,
		    const char *password_scheme)
{
	struct scram_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"scram_auth_request", 2048);
	request = p_new(pool, struct scram_auth_request, 1);
	request->pool = pool;
	request->password_scheme = password_scheme;

	struct auth *auth = auth_default_protocol();
	struct auth_scram_server_settings scram_set;

	i_zero(&scram_set);
	scram_set.hash_method = hash_method;

	if (mech_register_find(auth->reg,
			       t_strconcat(password_scheme,
					   "-PLUS", NULL)) == NULL) {
		scram_set.cbind_support =
			AUTH_SCRAM_CBIND_SERVER_SUPPORT_NONE;
	} else if (mech_register_find(auth->reg,
				    request->password_scheme) == NULL) {
		scram_set.cbind_support =
			AUTH_SCRAM_CBIND_SERVER_SUPPORT_REQUIRED;
	} else {
		scram_set.cbind_support =
			AUTH_SCRAM_CBIND_SERVER_SUPPORT_AVAILABLE;
	}

	auth_scram_server_init(&request->scram_server, pool,
			       &scram_set, &scram_server_backend);

	request->auth_request.pool = pool;
	return &request->auth_request;
}

static struct auth_request *mech_scram_sha1_auth_new(void)
{
	return mech_scram_auth_new(&hash_method_sha1, "SCRAM-SHA-1");
}

static struct auth_request *mech_scram_sha256_auth_new(void)
{
	return mech_scram_auth_new(&hash_method_sha256, "SCRAM-SHA-256");
}

static void mech_scram_auth_free(struct auth_request *auth_request)
{
	struct scram_auth_request *request =
		container_of(auth_request, struct scram_auth_request,
			     auth_request);

	auth_scram_server_deinit(&request->scram_server);
	pool_unref(&auth_request->pool);
}

const struct mech_module mech_scram_sha1 = {
	"SCRAM-SHA-1",

	.flags = MECH_SEC_MUTUAL_AUTH,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_scram_sha1_auth_new,
	mech_generic_auth_initial,
	mech_scram_auth_continue,
	mech_scram_auth_free,
};

const struct mech_module mech_scram_sha1_plus = {
	"SCRAM-SHA-1-PLUS",

	.flags = MECH_SEC_MUTUAL_AUTH | MECH_SEC_CHANNEL_BINDING,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_scram_sha1_auth_new,
	mech_generic_auth_initial,
	mech_scram_auth_continue,
	mech_scram_auth_free
};

const struct mech_module mech_scram_sha256 = {
	"SCRAM-SHA-256",

	.flags = MECH_SEC_MUTUAL_AUTH,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_scram_sha256_auth_new,
	mech_generic_auth_initial,
	mech_scram_auth_continue,
	mech_scram_auth_free,
};

const struct mech_module mech_scram_sha256_plus = {
	"SCRAM-SHA-256-PLUS",

	.flags = MECH_SEC_MUTUAL_AUTH | MECH_SEC_CHANNEL_BINDING,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_scram_sha256_auth_new,
	mech_generic_auth_initial,
	mech_scram_auth_continue,
	mech_scram_auth_free
};
