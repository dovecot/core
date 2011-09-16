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

struct scram_auth_request {
	struct auth_request auth_request;

	pool_t pool;
	unsigned int authenticated:1;

	/* sent: */
	char *server_first_message;
	unsigned char salt[16];
	unsigned char salted_password[SHA1_RESULTLEN];

	/* received: */
	char *gs2_cbind_flag;
	char *cnonce;
	char *snonce;
	char *client_first_message_bare;
	char *client_final_message_without_proof;
	buffer_t *proof;
};

static void Hi(const unsigned char *str, size_t str_size,
	       const unsigned char *salt, size_t salt_size, unsigned int i,
	       unsigned char result[SHA1_RESULTLEN])
{
	struct hmac_sha1_context ctx;
	unsigned char U[SHA1_RESULTLEN];
	size_t j, k;

	/* Calculate U1 */
	hmac_sha1_init(&ctx, str, str_size);
	hmac_sha1_update(&ctx, salt, salt_size);
	hmac_sha1_update(&ctx, "\0\0\0\1", 4);
	hmac_sha1_final(&ctx, U);

	memcpy(result, U, SHA1_RESULTLEN);

	/* Calculate U2 to Ui and Hi*/
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
	unsigned char snonce[65];
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
	base64_encode(request->salt, sizeof(request->salt), str);

	return t_strdup_printf("r=%s%s,s=%s,i=%i", request->cnonce,
			request->snonce, str_c(str), 4096);
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
	base64_encode(server_signature, sizeof(server_signature), str);

	return t_strdup_printf("v=%s", str_c(str));
}

static bool parse_scram_client_first(struct scram_auth_request *request,
				     const unsigned char *data, size_t size,
				     const char **error)
{
	const char *const *fields;
	const char *p;
	string_t *username;

	fields = t_strsplit(t_strndup(data, size), ",");

	if (str_array_length(fields) < 4) {
		*error = "Invalid initial client message";
		return FALSE;
	}

	switch (fields[0][0]) {
	case 'p':
		*error = "Channel binding not supported";
		return FALSE;
	case 'y':
	case 'n':
		request->gs2_cbind_flag = p_strdup(request->pool, fields[0]);
		break;
	default:
		*error = "Invalid GS2 header";
		return FALSE;
	}

	if (fields[1][0] != '\0') {
		*error = "authzid not supported";
		return FALSE;
	}

	if (fields[2][0] == 'm') {
		*error = "Mandatory extension(s) not supported";
		return FALSE;
	}

	if (fields[2][0] == 'n') {
		/* Unescape username */
		username = t_str_new(0);

		for (p = fields[2] + 2; *p != '\0'; p++) {
			if (p[0] == '=') {
				if (p[1] == '2' && p[2] == 'C') {
					str_append_c(username, ',');
				} else if (p[1] == '3' && p[2] == 'D') {
					str_append_c(username, '=');
				} else {
					*error = "Username contains "
						 "forbidden character(s)";
					return FALSE;
				}
				p += 2;
			} else if (p[0] == ',') {
				*error = "Username contains "
					 "forbidden character(s)";
				return FALSE;
			} else {
				str_append_c(username, *p);
			}
		}
		if (!auth_request_set_username(&request->auth_request,
					str_c(username), error))
				return FALSE;
	} else {
		*error = "Invalid username";
		return FALSE;
	}

	if (fields[3][0] == 'r')
		request->cnonce = p_strdup(request->pool, fields[3]+2);
	else {
		*error = "Invalid client nonce";
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
	Hi(credentials, size, request->salt, sizeof(request->salt), 4096,
			request->salted_password);

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

	if (!memcmp(client_signature, request->proof->data,
				request->proof->used))
		return TRUE;

	return FALSE;
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
			request->authenticated = TRUE;
			server_final_message = get_scram_server_final(request);
			auth_request_handler_reply_continue(auth_request,
					server_final_message,
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
				     const unsigned char *data,
				     size_t size ATTR_UNUSED,
				     const char **error)
{
	const char **fields;
	unsigned int field_count;
	const char *cbind_input;
	string_t *str;

	fields = t_strsplit((const char*)data, ",");
	field_count = str_array_length(fields);

	if (field_count < 3) {
		*error = "Invalid final client message";
		return FALSE;
	}

	cbind_input = t_strconcat(request->gs2_cbind_flag, ",,", NULL);
	str = t_str_new(MAX_BASE64_ENCODED_SIZE(strlen(cbind_input)));
	base64_encode(cbind_input, strlen(cbind_input), str);

	if (strcmp(fields[0], t_strconcat("c=", str_c(str), NULL))) {
		*error = "Invalid channel binding data";
		return FALSE;
	}

	if (strcmp(fields[1], t_strconcat("r=", request->cnonce,
					request->snonce, NULL))) {
		*error = "Wrong nonce";
		return FALSE;
	}

	if (fields[field_count-1][0] == 'p') {
		size_t len = strlen(&fields[field_count-1][2]);

		request->proof = buffer_create_dynamic(request->pool,
				MAX_BASE64_DECODED_SIZE(len));

		if ((base64_decode(&fields[field_count-1][2], len, NULL,
						request->proof) < 0)
				|| (request->proof->used != SHA1_RESULTLEN)) {
			*error = "Invalid base64 encoding "
				"or length for ClientProof";
			return FALSE;
		}
	} else {
		*error = "Invalid ClientProof";
		return FALSE;
	}

	str_array_remove(fields, fields[field_count-1]);
	request->client_final_message_without_proof = p_strdup(request->pool,
			t_strarray_join(fields, ","));

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

	if (request->authenticated) {
		/* authentication is done, we were just waiting the last (empty)
		   client response */
		auth_request_success(auth_request, NULL, 0);
		return;
	}

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

	if (error == NULL)
		error = "authentication failed";

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

	request->client_first_message_bare = NULL;

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
