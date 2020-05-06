
/*
 * SCRAM-SHA-1 SASL authentication, see RFC-5802
 *
 * Copyright (c) 2011-2016 Florian Zeitz <florob@babelmonkeys.de>
 *
 * This software is released under the MIT license.
 */

#include <limits.h>

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
	const char *gs2_cbind_flag;
	const char *cnonce;
	const char *client_first_message_bare;
	const char *client_final_message_without_proof;
	buffer_t *proof;

	/* stored */
	unsigned char *stored_key;
	unsigned char *server_key;
};

static const char *get_scram_server_first(struct scram_auth_request *request,
					  int iter, const char *salt)
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

	str = t_str_new(sizeof(snonce));
	str_printfa(str, "r=%s%s,s=%s,i=%d", request->cnonce, request->snonce,
		    salt, iter);
	return str_c(str);
}

static const char *get_scram_server_final(struct scram_auth_request *request)
{
	const struct hash_method *hmethod = request->hash_method;
	struct hmac_context ctx;
	const char *auth_message;
	unsigned char server_signature[hmethod->digest_size];
	string_t *str;

	auth_message = t_strconcat(request->client_first_message_bare, ",",
			request->server_first_message, ",",
			request->client_final_message_without_proof, NULL);

	hmac_init(&ctx, request->server_key, hmethod->digest_size, hmethod);
	hmac_update(&ctx, auth_message, strlen(auth_message));
	hmac_final(&ctx, server_signature);

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
	const char *const *fields, *login_username = NULL;
	const char *gs2_cbind_flag, *authzid, *username, *nonce;

	fields = t_strsplit(t_strndup(data, size), ",");
	if (str_array_length(fields) < 4) {
		*error_r = "Invalid initial client message";
		return FALSE;
	}
	gs2_cbind_flag = fields[0];
	authzid = fields[1];
	username = fields[2];
	nonce = fields[3];

	/* Order of fields is fixed:

	   client-first-message = gs2-header client-first-message-bare
	   gs2-header      = gs2-cbind-flag "," [ authzid ] ","
	   gs2-cbind-flag  = ("p=" cb-name) / "n" / "y"

	   client-first-message-bare = [reserved-mext ","]
                                       username "," nonce ["," extensions]
	   reserved-mext   = "m=" 1*(value-char)

	   username        = "n=" saslname
	   nonce           = "r=" c-nonce [s-nonce]

	   extensions      = attr-val *("," attr-val)
			       ;; All extensions are optional,
			       ;; i.e., unrecognized attributes
			       ;; not defined in this document
			       ;; MUST be ignored.
	   attr-val        = ALPHA "=" value

	   */
	switch (gs2_cbind_flag[0]) {
	case 'p':
		*error_r = "Channel binding not supported";
		return FALSE;
	case 'y':
	case 'n':
		request->gs2_cbind_flag =
			p_strdup(request->pool, gs2_cbind_flag);
		break;
	default:
		*error_r = "Invalid GS2 header";
		return FALSE;
	}

	if (authzid[0] == '\0')
		;
	else if (authzid[0] == 'a' && authzid[1] == '=') {
		/* Unescape authzid */
		login_username = scram_unescape_username(authzid + 2);

		if (login_username == NULL) {
			*error_r = "authzid escaping is invalid";
			return FALSE;
		}
	} else {
		*error_r = "Invalid authzid field";
		return FALSE;
	}
	if (username[0] == 'm') {
		*error_r = "Mandatory extension(s) not supported";
		return FALSE;
	}
	if (username[0] == 'n' && username[1] == '=') {
		/* Unescape username */
		username = scram_unescape_username(username + 2);
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
	if (login_username != NULL) {
		if (!auth_request_set_login_username(&request->auth_request,
						     login_username, error_r))
			return FALSE;
	}

	if (nonce[0] == 'r' && nonce[1] == '=')
		request->cnonce = p_strdup(request->pool, nonce+2);
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

static bool verify_credentials(struct scram_auth_request *request)
{
	const struct hash_method *hmethod = request->hash_method;
	struct hmac_context ctx;
	const char *auth_message;
	unsigned char client_key[hmethod->digest_size];
	unsigned char client_signature[hmethod->digest_size];
	unsigned char stored_key[hmethod->digest_size];
	size_t i;

	auth_message = t_strconcat(request->client_first_message_bare, ",",
			request->server_first_message, ",",
			request->client_final_message_without_proof, NULL);

	hmac_init(&ctx, request->stored_key, hmethod->digest_size, hmethod);
	hmac_update(&ctx, auth_message, strlen(auth_message));
	hmac_final(&ctx, client_signature);

	for (i = 0; i < sizeof(client_signature); i++)
		client_key[i] =
			((char*)request->proof->data)[i] ^ client_signature[i];

	hash_method_get_digest(hmethod, client_key, sizeof(client_key),
			       stored_key);

	safe_memset(client_key, 0, sizeof(client_key));
	safe_memset(client_signature, 0, sizeof(client_signature));

	return mem_equals_timing_safe(stored_key, request->stored_key, sizeof(stored_key));
}

static void credentials_callback(enum passdb_result result,
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

static bool parse_scram_client_final(struct scram_auth_request *request,
				     const unsigned char *data, size_t size,
				     const char **error_r)
{
	const struct hash_method *hmethod = request->hash_method;
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
