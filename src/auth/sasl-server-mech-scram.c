/* Copyright (c) 2011-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sha1.h"
#include "sha2.h"
#include "password-scheme.h"
#include "auth-scram-server.h"

#include "sasl-server-protected.h"
#include "sasl-server-mech-scram.h"

struct scram_auth_request {
	struct sasl_server_mech_request auth_request;

	struct auth_scram_server scram_server;
	struct auth_scram_key_data *key_data;
};

struct scram_auth_mech {
	struct sasl_server_mech mech;

	const struct hash_method *hash_method;
	const char *password_scheme;
};

static void
credentials_callback(struct sasl_server_mech_request *auth_request,
		     const struct sasl_passdb_result *result)
{
	struct scram_auth_request *request =
		container_of(auth_request, struct scram_auth_request,
			     auth_request);
	const struct scram_auth_mech *scram_mech =
		container_of(auth_request->mech,
			     const struct scram_auth_mech, mech);
	struct auth_scram_key_data *key_data = request->key_data;
	const char *error;
	const unsigned char *output;
	size_t output_len;
	bool end;

	request->key_data = NULL;
	switch (result->status) {
	case SASL_PASSDB_RESULT_OK:
		if (auth_scram_credentials_parse(key_data->hmethod,
						 scram_mech->password_scheme,
						 result->credentials.data,
						 result->credentials.size,
						 &key_data->iter_count,
						 &key_data->salt,
						 key_data->stored_key,
						 key_data->server_key,
						 &error) < 0) {
			e_info(auth_request->mech_event, "%s", error);
			sasl_server_request_failure(auth_request);
			break;
		}

		end = auth_scram_server_output(&request->scram_server,
					       &output, &output_len);
		i_assert(!end);
		sasl_server_request_output(auth_request, output, output_len);
		break;
	case SASL_PASSDB_RESULT_INTERNAL_FAILURE:
		sasl_server_request_internal_failure(auth_request);
		break;
	default:
		sasl_server_request_failure(auth_request);
		break;
	}
}

static bool
mech_scram_set_username(struct auth_scram_server *asserver,
			const char *username)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct sasl_server_mech_request *auth_request = &request->auth_request;

	return sasl_server_request_set_authid(auth_request,
					      SASL_SERVER_AUTHID_TYPE_USERNAME,
					      username);
}

static bool
mech_scram_set_login_username(struct auth_scram_server *asserver,
			      const char *username)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct sasl_server_mech_request *auth_request = &request->auth_request;

	return sasl_server_request_set_authzid(auth_request, username);
}

static void
mech_scram_start_channel_binding(struct auth_scram_server *asserver,
				 const char *type)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct sasl_server_mech_request *auth_request = &request->auth_request;

	sasl_server_request_start_channel_binding(auth_request, type);
}

static int
mech_scram_accept_channel_binding(struct auth_scram_server *asserver,
				  buffer_t **data_r)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct sasl_server_mech_request *auth_request = &request->auth_request;

	return sasl_server_request_accept_channel_binding(auth_request, data_r);
}

static int
mech_scram_credentials_lookup(struct auth_scram_server *asserver,
			      struct auth_scram_key_data *key_data)
{
	struct scram_auth_request *request =
		container_of(asserver, struct scram_auth_request, scram_server);
	struct sasl_server_mech_request *auth_request = &request->auth_request;
	const struct scram_auth_mech *scram_mech =
		container_of(auth_request->mech,
			     const struct scram_auth_mech, mech);

	request->key_data = key_data;
	sasl_server_request_lookup_credentials(auth_request,
					       scram_mech->password_scheme,
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

static void
mech_scram_auth_continue(struct sasl_server_mech_request *auth_request,
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
		switch (error_code) {
		case AUTH_SCRAM_SERVER_ERROR_NONE:
			i_unreached();
		case AUTH_SCRAM_SERVER_ERROR_PROTOCOL_VIOLATION:
			e_info(auth_request->mech_event, "%s", error);
			break;
		case AUTH_SCRAM_SERVER_ERROR_BAD_USERNAME:
		case AUTH_SCRAM_SERVER_ERROR_BAD_LOGIN_USERNAME:
		case AUTH_SCRAM_SERVER_ERROR_LOOKUP_FAILED:
			break;
		case AUTH_SCRAM_SERVER_ERROR_VERIFICATION_FAILED:
			e_info(auth_request->mech_event,
			       AUTH_LOG_MSG_PASSWORD_MISMATCH);
			break;
		}
		sasl_server_request_failure(auth_request);
		return;
	}
	if (ret == 0)
		return;

	if (!auth_scram_server_output(&request->scram_server,
				      &output, &output_len)) {
		sasl_server_request_output(auth_request, output, output_len);
		return;
	}

	sasl_server_request_success(auth_request, output, output_len);
}

static struct sasl_server_mech_request *
mech_scram_auth_new(const struct sasl_server_mech *mech, pool_t pool)
{
	struct sasl_server_instance *sinst = mech->sinst;
	const struct scram_auth_mech *scram_mech =
		container_of(mech, const struct scram_auth_mech, mech);
	struct scram_auth_request *request;

	request = p_new(pool, struct scram_auth_request, 1);

	struct auth_scram_server_settings scram_set;

	i_zero(&scram_set);
	scram_set.hash_method = scram_mech->hash_method;

	if (sasl_server_mech_find(
		sinst, t_strconcat(scram_mech->password_scheme,
				   "-PLUS", NULL)) == NULL) {
		scram_set.cbind_support =
			AUTH_SCRAM_CBIND_SERVER_SUPPORT_NONE;
	} else if (sasl_server_mech_find(sinst,
					 scram_mech->password_scheme) == NULL) {
		scram_set.cbind_support =
			AUTH_SCRAM_CBIND_SERVER_SUPPORT_REQUIRED;
	} else {
		scram_set.cbind_support =
			AUTH_SCRAM_CBIND_SERVER_SUPPORT_AVAILABLE;
	}

	auth_scram_server_init(&request->scram_server, pool,
			       &scram_set, &scram_server_backend);

	return &request->auth_request;
}

static void mech_scram_auth_free(struct sasl_server_mech_request *auth_request)
{
	struct scram_auth_request *request =
		container_of(auth_request, struct scram_auth_request,
			     auth_request);

	auth_scram_server_deinit(&request->scram_server);
}

static struct sasl_server_mech *mech_scram_mech_new(pool_t pool)
{
	struct scram_auth_mech *scram_mech;

	scram_mech = p_new(pool, struct scram_auth_mech, 1);

	return &scram_mech->mech;
}

const struct sasl_server_mech_funcs sasl_server_mech_scram_funcs = {
	.auth_new = mech_scram_auth_new,
	.auth_initial = sasl_server_mech_generic_auth_initial,
	.auth_continue = mech_scram_auth_continue,
	.auth_free = mech_scram_auth_free,

	.mech_new = mech_scram_mech_new,
};

static const struct sasl_server_mech_def mech_scram_sha1 = {
	.name = SASL_MECH_NAME_SCRAM_SHA_1,

	.flags = SASL_MECH_SEC_MUTUAL_AUTH,
	.passdb_need = SASL_MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	.funcs = &sasl_server_mech_scram_funcs,
};

static const struct sasl_server_mech_def mech_scram_sha1_plus = {
	.name = SASL_MECH_NAME_SCRAM_SHA_1_PLUS,

	.flags = SASL_MECH_SEC_MUTUAL_AUTH | SASL_MECH_SEC_CHANNEL_BINDING,
	.passdb_need = SASL_MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	.funcs = &sasl_server_mech_scram_funcs,
};

static const struct sasl_server_mech_def mech_scram_sha256 = {
	.name = SASL_MECH_NAME_SCRAM_SHA_256,

	.flags = SASL_MECH_SEC_MUTUAL_AUTH,
	.passdb_need = SASL_MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	.funcs = &sasl_server_mech_scram_funcs,
};

static const struct sasl_server_mech_def mech_scram_sha256_plus = {
	.name = SASL_MECH_NAME_SCRAM_SHA_256_PLUS,

	.flags = SASL_MECH_SEC_MUTUAL_AUTH | SASL_MECH_SEC_CHANNEL_BINDING,
	.passdb_need = SASL_MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	.funcs = &sasl_server_mech_scram_funcs,
};

void sasl_server_mech_register_scram(
	struct sasl_server_instance *sinst,
	const struct sasl_server_mech_def *mech_def,
	const struct hash_method *hash_method, const char *password_scheme)
{
	struct sasl_server_mech *mech;
	struct scram_auth_mech *scram_mech;

	i_assert(mech_def->funcs == &sasl_server_mech_scram_funcs);

	mech = sasl_server_mech_register(sinst, mech_def, NULL);

	scram_mech = container_of(mech, struct scram_auth_mech, mech);
	scram_mech->hash_method = hash_method;
	scram_mech->password_scheme = p_strdup(mech->pool, password_scheme);
}

void sasl_server_mech_register_scram_sha1(
	struct sasl_server_instance *sinst)
{
	sasl_server_mech_register_scram(sinst, &mech_scram_sha1,
					&hash_method_sha1, "SCRAM-SHA-1");
}

void sasl_server_mech_register_scram_sha1_plus(
	struct sasl_server_instance *sinst)
{
	sasl_server_mech_register_scram(sinst, &mech_scram_sha1_plus,
					&hash_method_sha1, "SCRAM-SHA-1");
}

void sasl_server_mech_register_scram_sha256(
	struct sasl_server_instance *sinst)
{
	sasl_server_mech_register_scram(sinst, &mech_scram_sha256,
					&hash_method_sha256, "SCRAM-SHA-256");
}

void sasl_server_mech_register_scram_sha256_plus(
	struct sasl_server_instance *sinst)
{
	sasl_server_mech_register_scram(sinst, &mech_scram_sha256_plus,
					&hash_method_sha256, "SCRAM-SHA-256");
}
