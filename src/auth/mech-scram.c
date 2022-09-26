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

static const char *get_scram_server_final(struct scram_auth_request *request)
{
	const struct hash_method *hmethod = request->hash_method;
	struct hmac_context ctx;
	const char *auth_message;
	unsigned char server_signature[hmethod->digest_size];
	string_t *str;

	/* RFC 5802, Section 3:

	   AuthMessage     := client-first-message-bare + "," +
	                      server-first-message + "," +
	                      client-final-message-without-proof
	   ServerSignature := HMAC(ServerKey, AuthMessage)
	 */
	auth_message = t_strconcat(request->client_first_message_bare, ",",
			request->server_first_message, ",",
			request->client_final_message_without_proof, NULL);

	hmac_init(&ctx, request->server_key, hmethod->digest_size, hmethod);
	hmac_update(&ctx, auth_message, strlen(auth_message));
	hmac_final(&ctx, server_signature);

	/* RFC 5802, Section 7:

	   server-final-message = (server-error / verifier)
	                     ["," extensions]

	   verifier        = "v=" base64
	                     ;; base-64 encoded ServerSignature.

	 */
	str = t_str_new(2 + MAX_BASE64_ENCODED_SIZE(sizeof(server_signature)));
	str_append(str, "v=");
	base64_encode(server_signature, sizeof(server_signature), str);

	return str_c(str);
}

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
			get_scram_server_first(request, iter_count, salt));

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

static bool
parse_scram_client_final(struct scram_auth_request *request,
			 const unsigned char *data, size_t size,
			 const char **error_r)
{
	const struct hash_method *hmethod = request->hash_method;
	const char **fields, *cbind_input, *nonce_str;
	unsigned int field_count;
	string_t *str;

	/* RFC 5802, Section 7:

	   client-final-message-without-proof =
	                     channel-binding "," nonce [","
	                     extensions]
	   client-final-message =
	                     client-final-message-without-proof "," proof
	 */
	fields = t_strsplit(t_strndup(data, size), ",");
	field_count = str_array_length(fields);
	if (field_count < 3) {
		*error_r = "Invalid final client message";
		return FALSE;
	}

	/* channel-binding = "c=" base64
	                     ;; base64 encoding of cbind-input.

	   cbind-data      = 1*OCTET
	   cbind-input     = gs2-header [ cbind-data ]
	                     ;; cbind-data MUST be present for
	                     ;; gs2-cbind-flag of "p" and MUST be absent
	                     ;; for "y" or "n".
	 */
	cbind_input = request->gs2_header;
	str = t_str_new(2 + MAX_BASE64_ENCODED_SIZE(strlen(cbind_input)));
	str_append(str, "c=");
	base64_encode(cbind_input, strlen(cbind_input), str);

	if (strcmp(fields[0], str_c(str)) != 0) {
		*error_r = "Invalid channel binding data";
		return FALSE;
	}

	/* nonce           = "r=" c-nonce [s-nonce]
	                     ;; Second part provided by server.
	   c-nonce         = printable
	   s-nonce         = printable
	 */
	nonce_str = t_strconcat("r=", request->cnonce, request->snonce, NULL);
	if (strcmp(fields[1], nonce_str) != 0) {
		*error_r = "Wrong nonce";
		return FALSE;
	}

	/* proof           = "p=" base64
	 */
	if (fields[field_count-1][0] == 'p') {
		size_t len = strlen(&fields[field_count-1][2]);

		request->proof = buffer_create_dynamic(request->pool,
					MAX_BASE64_DECODED_SIZE(len));
		if (base64_decode(&fields[field_count-1][2], len,
				  request->proof) < 0) {
			*error_r = "Invalid base64 encoding";
			return FALSE;
		}
		if (request->proof->used != hmethod->digest_size) {
			*error_r = "Invalid ClientProof length";
			return FALSE;
		}
	} else {
		*error_r = "Invalid ClientProof";
		return FALSE;
	}

	(void)str_array_remove(fields, fields[field_count-1]);
	request->client_final_message_without_proof =
		p_strdup(request->pool, t_strarray_join(fields, ","));

	return TRUE;
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
		if (parse_scram_client_first(request, data,
					     data_size, &error)) {
			auth_request_lookup_credentials(
				&request->auth_request,
				request->password_scheme,
				credentials_callback);
			return;
		}
	} else {
		/* Received client-final-message */
		if (parse_scram_client_final(request, data, data_size,
					     &error)) {
			if (!verify_credentials(request)) {
				e_info(auth_request->mech_event,
				       AUTH_LOG_MSG_PASSWORD_MISMATCH);
			} else {
				server_final_message =
					get_scram_server_final(request);
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
