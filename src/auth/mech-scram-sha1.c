/*
 * SCRAM-SHA-1 SASL authentication, see RFC-5802
 *
 * Copyright (c) 2011 Florian Zeitz <florob@babelmonkeys.de>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "base64.h"
#include "buffer.h"
#include "hmac-sha1.h"
#include "randgen.h"
#include "safe-memset.h"
#include "str.h"
#include "strfuncs.h"
#include "mech.h"

/* SCRAM hash iteration count. RFC says it SHOULD be at least 4096 */
#define SCRAM_ITERATE_COUNT 4096
/* s-nonce length */
#define SCRAM_SERVER_NONCE_LEN 64

struct scram_auth_request {
	struct auth_request auth_request;

	pool_t pool;

	/* sent: */
	const char *server_first_message;
	unsigned char salt[16];
	unsigned char salted_password[SHA1_RESULTLEN];

	/* received: */
	const char *gs2_cbind_flag;
	const char *cnonce;
	const char *snonce;
	const char *client_first_message_bare;
	const char *client_final_message_without_proof;
	buffer_t *proof;
};

static void Hi(const unsigned char *str, size_t str_size,
	       const unsigned char *salt, size_t salt_size, unsigned int i,
	       unsigned char result[SHA1_RESULTLEN])
{
	struct hmac_sha1_context ctx;
	unsigned char U[SHA1_RESULTLEN];
	unsigned int j, k;

	/* Calculate U1 */
	hmac_sha1_init(&ctx, str, str_size);
	hmac_sha1_update(&ctx, salt, salt_size);
	hmac_sha1_update(&ctx, "\0\0\0\1", 4);
	hmac_sha1_final(&ctx, U);

	memcpy(result, U, SHA1_RESULTLEN);

	/* Calculate U2 to Ui and Hi */
	for (j = 2; j <= i; j++) {
		hmac_sha1_init(&ctx, str, str_size);
		hmac_sha1_update(&ctx, U, sizeof(U));
		hmac_sha1_final(&ctx, U);
		for (k = 0; k < SHA1_RESULTLEN; k++)
			result[k] ^= U[k];
	}
}

static const char *get_scram_server_first(struct scram_auth_request *request)
{
	unsigned char snonce[SCRAM_SERVER_NONCE_LEN+1];
	string_t *str;
	size_t i;

	random_fill(snonce, sizeof(snonce)-1);

	/* make sure snonce is printable and does not contain ',' */
	for (i = 0; i < sizeof(snonce)-1; i++) {
		snonce[i] = (snonce[i] % ('~' - '!')) + '!';
		if (snonce[i] == ',')
			snonce[i] = '~';
	}
	snonce[sizeof(snonce)-1] = '\0';
	request->snonce = p_strndup(request->pool, snonce, sizeof(snonce));

	random_fill(request->salt, sizeof(request->salt));

	str = t_str_new(MAX_BASE64_ENCODED_SIZE(sizeof(request->salt)));
	str_printfa(str, "r=%s%s,s=", request->cnonce, request->snonce);
	base64_encode(request->salt, sizeof(request->salt), str);
	str_printfa(str, ",i=%d", SCRAM_ITERATE_COUNT);
	return str_c(str);
}

static const char *get_scram_server_final(struct scram_auth_request *request)
{
	struct hmac_sha1_context ctx;
	const char *auth_message;
	unsigned char server_key[SHA1_RESULTLEN];
	unsigned char server_signature[SHA1_RESULTLEN];
	string_t *str;

	auth_message = t_strconcat(request->client_first_message_bare, ",",
			request->server_first_message, ",",
			request->client_final_message_without_proof, NULL);

	hmac_sha1_init(&ctx, request->salted_password,
		       sizeof(request->salted_password));
	hmac_sha1_update(&ctx, "Server Key", 10);
	hmac_sha1_final(&ctx, server_key);

	safe_memset(request->salted_password, 0,
		    sizeof(request->salted_password));

	hmac_sha1_init(&ctx, server_key, sizeof(server_key));
	hmac_sha1_update(&ctx, auth_message, strlen(auth_message));
	hmac_sha1_final(&ctx, server_signature);

	str = t_str_new(MAX_BASE64_ENCODED_SIZE(sizeof(server_signature)));
	str_append(str, "v=");
	base64_encode(server_signature, sizeof(server_signature), str);

	return str_c(str);
}

static const char *scram_unescape_username(const char *in)
{
	string_t *out;

	out = t_str_new(64);
	for (; *in != '\0'; in++) {
		i_assert(in[0] != ','); /* strsplit should have caught this */

		if (in[0] == '=') {
			if (in[1] == '2' && in[2] == 'C')
				str_append_c(out, ',');
			else if (in[1] == '3' && in[2] == 'D')
				str_append_c(out, '=');
			else
				return NULL;
			in += 2;
		} else {
			str_append_c(out, *in);
		}
	}
	return str_c(out);
}

static bool parse_scram_client_first(struct scram_auth_request *request,
				     const unsigned char *data, size_t size,
				     const char **error_r)
{
	const char *const *fields;

	fields = t_strsplit(t_strndup(data, size), ",");
	if (str_array_length(fields) < 4) {
		*error_r = "Invalid initial client message";
		return FALSE;
	}

	switch (fields[0][0]) {
	case 'p':
		*error_r = "Channel binding not supported";
		return FALSE;
	case 'y':
	case 'n':
		request->gs2_cbind_flag = p_strdup(request->pool, fields[0]);
		break;
	default:
		*error_r = "Invalid GS2 header";
		return FALSE;
	}

	if (fields[1][0] != '\0') {
		*error_r = "authzid not supported";
		return FALSE;
	}
	if (fields[2][0] == 'm') {
		*error_r = "Mandatory extension(s) not supported";
		return FALSE;
	}
	if (fields[2][0] == 'n') {
		/* Unescape username */
		const char *username =
			scram_unescape_username(fields[2] + 2);

		if (username == NULL) {
			*error_r = "Username escaping is invalid";
			return FALSE;
		}
		if (!auth_request_set_username(&request->auth_request,
					       username, error_r))
			return FALSE;
	} else {
		*error_r = "Invalid username field";
		return FALSE;
	}

	if (fields[3][0] == 'r')
		request->cnonce = p_strdup(request->pool, fields[3]+2);
	else {
		*error_r = "Invalid client nonce";
		return FALSE;
	}

	/* This works only without channel binding support,
	   otherwise the GS2 header doesn't have a fixed length */
	request->client_first_message_bare =
		p_strndup(request->pool, data + 3, size - 3);
	return TRUE;
}

static bool verify_credentials(struct scram_auth_request *request,
			       const unsigned char *credentials, size_t size)
{
	struct hmac_sha1_context ctx;
	const char *auth_message;
	unsigned char client_key[SHA1_RESULTLEN];
	unsigned char client_signature[SHA1_RESULTLEN];
	unsigned char stored_key[SHA1_RESULTLEN];
	size_t i;

	/* FIXME: credentials should be SASLprepped UTF8 data here */
	Hi(credentials, size, request->salt, sizeof(request->salt),
	   SCRAM_ITERATE_COUNT, request->salted_password);

	hmac_sha1_init(&ctx, request->salted_password,
			sizeof(request->salted_password));
	hmac_sha1_update(&ctx, "Client Key", 10);
	hmac_sha1_final(&ctx, client_key);

	sha1_get_digest(client_key, sizeof(client_key), stored_key);

	auth_message = t_strconcat(request->client_first_message_bare, ",",
			request->server_first_message, ",",
			request->client_final_message_without_proof, NULL);

	hmac_sha1_init(&ctx, stored_key, sizeof(stored_key));
	hmac_sha1_update(&ctx, auth_message, strlen(auth_message));
	hmac_sha1_final(&ctx, client_signature);

	for (i = 0; i < sizeof(client_signature); i++)
		client_signature[i] ^= client_key[i];

	safe_memset(client_key, 0, sizeof(client_key));
	safe_memset(stored_key, 0, sizeof(stored_key));

	return memcmp(client_signature, request->proof->data,
		      request->proof->used) == 0;
}

static void credentials_callback(enum passdb_result result,
				 const unsigned char *credentials, size_t size,
				 struct auth_request *auth_request)
{
	struct scram_auth_request *request =
		(struct scram_auth_request *)auth_request;
	const char *server_final_message;

	switch (result) {
	case PASSDB_RESULT_OK:
		if (!verify_credentials(request, credentials, size)) {
			auth_request_log_info(auth_request, "scram-sha-1",
					      "password mismatch");
			auth_request_fail(auth_request);
		} else {
			server_final_message = get_scram_server_final(request);
			auth_request_success(auth_request, server_final_message,
					     strlen(server_final_message));
		}
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(auth_request);
		break;
	default:
		auth_request_fail(auth_request);
		break;
	}
}

static bool parse_scram_client_final(struct scram_auth_request *request,
				     const unsigned char *data, size_t size,
				     const char **error_r)
{
	const char **fields, *cbind_input, *nonce_str;
	unsigned int field_count;
	string_t *str;

	fields = t_strsplit(t_strndup(data, size), ",");
	field_count = str_array_length(fields);
	if (field_count < 3) {
		*error_r = "Invalid final client message";
		return FALSE;
	}

	cbind_input = t_strconcat(request->gs2_cbind_flag, ",,", NULL);
	str = t_str_new(MAX_BASE64_ENCODED_SIZE(strlen(cbind_input)));
	str_append(str, "c=");
	base64_encode(cbind_input, strlen(cbind_input), str);

	if (strcmp(fields[0], str_c(str)) != 0) {
		*error_r = "Invalid channel binding data";
		return FALSE;
	}

	nonce_str = t_strconcat("r=", request->cnonce, request->snonce, NULL);
	if (strcmp(fields[1], nonce_str) != 0) {
		*error_r = "Wrong nonce";
		return FALSE;
	}

	if (fields[field_count-1][0] == 'p') {
		size_t len = strlen(&fields[field_count-1][2]);

		request->proof = buffer_create_dynamic(request->pool,
					MAX_BASE64_DECODED_SIZE(len));
		if (base64_decode(&fields[field_count-1][2], len, NULL,
				  request->proof) < 0) {
			*error_r = "Invalid base64 encoding";
			return FALSE;
		}
		if (request->proof->used != SHA1_RESULTLEN) {
			*error_r = "Invalid ClientProof length";
			return FALSE;
		}
	} else {
		*error_r = "Invalid ClientProof";
		return FALSE;
	}

	str_array_remove(fields, fields[field_count-1]);
	request->client_final_message_without_proof =
		p_strdup(request->pool, t_strarray_join(fields, ","));

	auth_request_lookup_credentials(&request->auth_request, "PLAIN",
					credentials_callback);
	return TRUE;
}

static void mech_scram_sha1_auth_continue(struct auth_request *auth_request,
					  const unsigned char *data,
					  size_t data_size)
{
	struct scram_auth_request *request =
		(struct scram_auth_request *)auth_request;
	const char *error = NULL;

	if (!request->client_first_message_bare) {
		/* Received client-first-message */
		if (parse_scram_client_first(request, data,
					     data_size, &error)) {
			request->server_first_message = p_strdup(request->pool,
					get_scram_server_first(request));
			auth_request_handler_reply_continue(auth_request,
					request->server_first_message,
					strlen(request->server_first_message));
			return;
		}
	} else {
		/* Received client-final-message */
		if (parse_scram_client_final(request, data, data_size, &error))
			return;
	}

	if (error != NULL)
		auth_request_log_info(auth_request, "scram-sha-1", "%s", error);
	auth_request_fail(auth_request);
}

static struct auth_request *mech_scram_sha1_auth_new(void)
{
	struct scram_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create("scram_sha1_auth_request", 2048);
	request = p_new(pool, struct scram_auth_request, 1);
	request->pool = pool;

	request->auth_request.pool = pool;
	return &request->auth_request;
}

const struct mech_module mech_scram_sha1 = {
	"SCRAM-SHA-1",

	.flags = MECH_SEC_MUTUAL_AUTH,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	mech_scram_sha1_auth_new,
	mech_generic_auth_initial,
	mech_scram_sha1_auth_continue,
	mech_generic_auth_free
};
