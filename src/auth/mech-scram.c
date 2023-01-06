/*
 * SCRAM-SHA-1 SASL authentication, see RFC-5802
 *
 * Copyright (c) 2011-2016 Florian Zeitz <florob@babelmonkeys.de>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "base64.h"
#include "buffer.h"
#include "hmac.h"
#include "sha1.h"
#include "sha2.h"
#include "randgen.h"
#include "safe-memset.h"
#include "str.h"
#include "strfuncs.h"
#include "strnum.h"
#include "password-scheme.h"
#include "mech.h"
#include "mech-scram.h"

/* s-nonce length */
#define SCRAM_SERVER_NONCE_LEN 64

struct scram_auth_request {
	struct auth_request auth_request;

	pool_t pool;

	const struct hash_method *hash_method;
	const char *password_scheme;

	/* sent: */
	const char *server_first_message;
	const char *snonce;

	/* received: */
	const char *gs2_header;
	const char *cnonce;
	const char *client_first_message_bare;
	const char *client_final_message_without_proof;
	buffer_t *proof;

	/* stored */
	unsigned char *stored_key;
	unsigned char *server_key;
};

#include "auth-scram-server.c"

static void
credentials_callback(enum passdb_result result,
		     const unsigned char *credentials, size_t size,
		     struct auth_request *auth_request)
{
	struct scram_auth_request *request =
		(struct scram_auth_request *)auth_request;
	const char *salt, *error;
	unsigned int iter_count;

	switch (result) {
	case PASSDB_RESULT_OK:
		if (scram_scheme_parse(request->hash_method,
				       request->password_scheme,
				       credentials, size, &iter_count, &salt,
				       request->stored_key, request->server_key,
				       &error) < 0) {
			e_info(auth_request->mech_event,
			       "%s", error);
			auth_request_fail(auth_request);
			break;
		}

		request->server_first_message = p_strdup(request->pool,
			str_c(auth_scram_get_server_first(request, iter_count, salt)));

		auth_request_handler_reply_continue(auth_request,
					request->server_first_message,
					strlen(request->server_first_message));
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(auth_request);
		break;
	default:
		auth_request_fail(auth_request);
		break;
	}
}

void mech_scram_auth_continue(struct auth_request *auth_request,
			      const unsigned char *data, size_t data_size)
{
	struct scram_auth_request *request =
		(struct scram_auth_request *)auth_request;
	const char *error = NULL;
	const char *server_final_message;
	size_t len;

	if (request->client_first_message_bare == NULL) {
		/* Received client-first-message */
		if (auth_scram_parse_client_first(request, data,
						  data_size, &error) >= 0) {
			auth_request_lookup_credentials(
				&request->auth_request,
				request->password_scheme,
				credentials_callback);
			return;
		}
	} else {
		/* Received client-final-message */
		if (auth_scram_parse_client_final(request, data, data_size,
						  &error) >= 0) {
			if (!auth_scram_server_verify_credentials(request)) {
				e_info(auth_request->mech_event,
				       AUTH_LOG_MSG_PASSWORD_MISMATCH);
			} else {
				server_final_message =
					str_c(auth_scram_get_server_final(request));
				len = strlen(server_final_message);
				auth_request_success(auth_request,
						     server_final_message, len);
				return;
			}
		}
	}

	if (error != NULL)
		e_info(auth_request->mech_event, "%s", error);
	auth_request_fail(auth_request);
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

	request->hash_method = hash_method;
	request->password_scheme = password_scheme;

	request->stored_key = p_malloc(pool, hash_method->digest_size);
	request->server_key = p_malloc(pool, hash_method->digest_size);

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

const struct mech_module mech_scram_sha1 = {
	"SCRAM-SHA-1",

	.flags = MECH_SEC_MUTUAL_AUTH,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_scram_sha1_auth_new,
	mech_generic_auth_initial,
	mech_scram_auth_continue,
	mech_generic_auth_free
};

const struct mech_module mech_scram_sha256 = {
	"SCRAM-SHA-256",

	.flags = MECH_SEC_MUTUAL_AUTH,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_scram_sha256_auth_new,
	mech_generic_auth_initial,
	mech_scram_auth_continue,
	mech_generic_auth_free
};
