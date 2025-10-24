/* Copyright (c) 2021-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strnum.h"
#include "buffer.h"
#include "array.h"
#include "base64.h"
#include "hmac.h"
#include "sha1.h"
#include "sha2.h"
#include "randgen.h"
#include "safe-memset.h"

#include "auth-gs2.h"
#include "auth-scram-client.h"

/* c-nonce length */
#define SCRAM_CLIENT_NONCE_LEN 64
/* Max iteration count accepted by the client */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#  define SCRAM_MAX_ITERATE_COUNT (128 * 4096)
#else
#  define SCRAM_MAX_ITERATE_COUNT (2 * 4096)
#endif

void auth_scram_client_init(struct auth_scram_client *client_r, pool_t pool,
			    const struct auth_scram_client_settings *set)
{
	i_assert(set->hash_method != NULL);

	i_zero(client_r);
	client_r->pool = pool;
	client_r->set = *set;
}

void auth_scram_client_deinit(struct auth_scram_client *client)
{
	if (client->server_signature != NULL) {
		i_assert(client->set.hash_method != NULL);
		safe_memset(client->server_signature, 0,
			    client->set.hash_method->digest_size);
	}
}

static void
auth_scram_generate_cnonce(struct auth_scram_client *client)
{
	unsigned char cnonce[SCRAM_CLIENT_NONCE_LEN+1];
	size_t i;

	random_fill(cnonce, sizeof(cnonce)-1);

	/* Make sure cnonce is printable and does not contain ',' */
	for (i = 0; i < sizeof(cnonce) - 1; i++) {
		cnonce[i] = (cnonce[i] % ('~' - '!')) + '!';
		if (cnonce[i] == ',')
			cnonce[i] = '~';
	}
	cnonce[sizeof(cnonce)-1] = '\0';
	client->nonce = p_strdup(client->pool, (char *)cnonce);
}

static string_t *auth_scram_get_client_first(struct auth_scram_client *client)
{
	const char *cbind_type = client->set.cbind_type;
	enum auth_scram_cbind_server_support cbind_support =
		client->set.cbind_support;
	struct auth_gs2_header gs2_header;
	const char *cfm, *cfm_bare;
	string_t *str;
	size_t cfm_bare_offset;

	/* RFC 5802, Section 7:

	   client-first-message = gs2-header client-first-message-bare
	   gs2-header      = gs2-cbind-flag "," [ authzid ] ","

	   gs2-cbind-flag  = ("p=" cb-name) / "n" / "y"

	   authzid         = "a=" saslname
	                     ;; Protocol specific.

	   client-first-message-bare = [reserved-mext ","]
	                     username "," nonce ["," extensions]

	   username        = "n=" saslname

	   nonce           = "r=" c-nonce [s-nonce]

	   extensions      = attr-val *("," attr-val)
	                     ;; All extensions are optional,
	                     ;; i.e., unrecognized attributes
	                     ;; not defined in this document
	                     ;; MUST be ignored.
	   attr-val        = ALPHA "=" value
	 */

	auth_scram_generate_cnonce(client);

	i_zero(&gs2_header);
	if (cbind_type == NULL) {
		gs2_header.cbind.status =
			AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT;
	} else if (cbind_support == AUTH_SCRAM_CBIND_SERVER_SUPPORT_NONE) {
		gs2_header.cbind.status =
			AUTH_GS2_CBIND_STATUS_NO_SERVER_SUPPORT;
	} else {
		gs2_header.cbind.status = AUTH_GS2_CBIND_STATUS_PROVIDED;
		gs2_header.cbind.name = cbind_type;
	}
	gs2_header.authzid = client->set.authzid,

	str = t_str_new(256);
	auth_gs2_header_encode(&gs2_header, str);

	cfm_bare_offset = str_len(str);
	str_append(str, "n=");
	auth_gs2_encode_username(client->set.authid, str);
	str_append(str, ",r=");
	str_append(str, client->nonce);

	cfm = str_c(str);
	cfm_bare = cfm + cfm_bare_offset;

	client->gs2_header = p_strndup(client->pool, cfm, cfm_bare_offset);
	client->client_first_message_bare = p_strdup(client->pool, cfm_bare);
	return str;
}

static int
auth_scram_parse_server_first(struct auth_scram_client *client,
			      const unsigned char *input, size_t input_len,
			      const char **error_r)
{
	const char **fields;
	unsigned int field_count, iter;
	const char *nonce, *salt, *iter_str;
	size_t salt_len;

	/* RFC 5802, Section 7:

	   server-first-message =
	                     [reserved-mext ","] nonce "," salt ","
	                     iteration-count ["," extensions]
	 */

	fields = t_strsplit(t_strndup(input, input_len), ",");
	field_count = str_array_length(fields);
	if (field_count < 3) {
		*error_r = "Invalid first server message";
		return -1;
	}

	nonce = fields[0];
	salt = fields[1];
	iter_str = fields[2];

	/* reserved-mext   = "m=" 1*(value-char)
	 */
	if (nonce[0] == 'm') {
		*error_r = "Mandatory extension(s) not supported";
		return -1;
	}

	/* nonce           = "r=" c-nonce [s-nonce]
	                     ;; Second part provided by server.
	   c-nonce         = printable
	   s-nonce         = printable
	 */
	if (nonce[0] != 'r' || nonce[1] != '=') {
		*error_r = "Invalid nonce field in first server message";
		return -1;
	}
	if (!str_begins_with(&nonce[2], client->nonce)) {
		*error_r = "Incorrect nonce in first server message";
		return -1;
	}
	nonce += 2;

	/* salt            = "s=" base64
	 */
	if (salt[0] != 's' || salt[1] != '=') {
		*error_r = "Invalid salt field in first server message";
		return -1;
	}
	salt_len = strlen(&salt[2]);
	client->salt = buffer_create_dynamic(
		client->pool, MAX_BASE64_DECODED_SIZE(salt_len));
	if (base64_decode(&salt[2], salt_len, client->salt) < 0) {
		*error_r = "Invalid base64 encoding for salt field in first server message";
		return -1;
	}

	/* iteration-count = "i=" posit-number
	                     ;; A positive number.
	 */
	if (iter_str[0] != 'i' || iter_str[1] != '=' ||
	    str_to_uint(&iter_str[2], &iter) < 0) {
		*error_r = "Invalid iteration count field in first server message";
		return -1;
	}
	if (iter > SCRAM_MAX_ITERATE_COUNT) {
		*error_r = "Iteration count out of range in first server message";
		return -1;
	}

	client->server_first_message =
		p_strndup(client->pool, input, input_len);
	client->nonce = p_strdup(client->pool, nonce);
	client->iter = iter;
	return 0;
}

static string_t *auth_scram_get_client_final(struct auth_scram_client *client)
{
	const struct hash_method *hmethod = client->set.hash_method;
	const buffer_t *cbind_data = client->set.cbind_data;
	unsigned char salted_password[hmethod->digest_size];
	unsigned char client_key[hmethod->digest_size];
	unsigned char stored_key[hmethod->digest_size];
	unsigned char client_signature[hmethod->digest_size];
	unsigned char client_proof[hmethod->digest_size];
	unsigned char server_key[hmethod->digest_size];
	struct hmac_context ctx;
	const void *cbind_input;
	size_t cbind_input_size;
	string_t *auth_message, *str;
	unsigned int k;

	i_assert(hmethod != NULL);
	i_assert(client->salt != NULL);

	/* RFC 5802, Section 7:

	   client-final-message-without-proof =
	                     channel-binding "," nonce [","
	                     extensions]

	   channel-binding = "c=" base64
	                     ;; base64 encoding of cbind-input.

	   cbind-data      = 1*OCTET
	   cbind-input     = gs2-header [ cbind-data ]
	                     ;; cbind-data MUST be present for
	                     ;; gs2-cbind-flag of "p" and MUST be absent
	                     ;; for "y" or "n".

	   nonce           = "r=" c-nonce [s-nonce]
	                     ;; Second part provided by server.
	   c-nonce         = printable
	   s-nonce         = printable
	 */

	if (client->gs2_header[0] != 'p') {
		i_assert(cbind_data == NULL);
		cbind_input = client->gs2_header;
		cbind_input_size = strlen(client->gs2_header);
	} else {
		size_t gs2_header_len = strlen(client->gs2_header);
		buffer_t *cbind_buf;
		i_assert(cbind_data != NULL);
		cbind_buf = t_buffer_create(gs2_header_len + cbind_data->used);
		buffer_append(cbind_buf, client->gs2_header, gs2_header_len);
		buffer_append_buf(cbind_buf, cbind_data, 0, SIZE_MAX);
		cbind_input = cbind_buf->data;
		cbind_input_size = cbind_buf->used;
	}
	str = t_str_new(256);
	str_append(str, "c=");
	base64_encode(cbind_input, cbind_input_size, str);
	str_append(str, ",r=");
	str_append(str, client->nonce);

	/* SaltedPassword  := Hi(Normalize(password), salt, i)
	     FIXME: credentials should be SASLprepped UTF8 data here */
	auth_scram_hi(hmethod,
		      (const unsigned char *)client->set.password,
		      strlen(client->set.password),
		      client->salt->data, client->salt->used,
		      client->iter, salted_password);

	/* ClientKey       := HMAC(SaltedPassword, "Client Key") */
	hmac_init(&ctx, salted_password, sizeof(salted_password), hmethod);
	hmac_update(&ctx, "Client Key", 10);
	hmac_final(&ctx, client_key);

	/* StoredKey       := H(ClientKey) */
	hash_method_get_digest(hmethod, client_key, sizeof(client_key),
			       stored_key);

	/* AuthMessage     := client-first-message-bare + "," +
	                      server-first-message + "," +
	                      client-final-message-without-proof
	 */
	auth_message = t_str_new(512);
	str_append(auth_message, client->client_first_message_bare);
	str_append_c(auth_message, ',');
	str_append(auth_message, client->server_first_message);
	str_append_c(auth_message, ',');
	str_append_str(auth_message, str);

	/* ClientSignature := HMAC(StoredKey, AuthMessage) */
	hmac_init(&ctx, stored_key, sizeof(stored_key), hmethod);
	hmac_update(&ctx, str_data(auth_message), str_len(auth_message));
	hmac_final(&ctx, client_signature);

	/* ClientProof     := ClientKey XOR ClientSignature */
	for (k = 0; k < hmethod->digest_size; k++)
		client_proof[k] = client_key[k] ^ client_signature[k];

	safe_memset(client_key, 0, sizeof(client_key));
	safe_memset(stored_key, 0, sizeof(stored_key));
	safe_memset(client_signature, 0, sizeof(client_signature));

	/* ServerKey       := HMAC(SaltedPassword, "Server Key") */
	hmac_init(&ctx, salted_password, sizeof(salted_password), hmethod);
	hmac_update(&ctx, "Server Key", 10);
	hmac_final(&ctx, server_key);

	/* ServerSignature := HMAC(ServerKey, AuthMessage) */
	client->server_signature =
		p_malloc(client->pool, hmethod->digest_size);
	hmac_init(&ctx, server_key, sizeof(server_key), hmethod);
	hmac_update(&ctx, str_data(auth_message), str_len(auth_message));
	hmac_final(&ctx, client->server_signature);

	safe_memset(salted_password, 0, sizeof(salted_password));

	/* client-final-message =
	                     client-final-message-without-proof "," proof

	   proof           = "p=" base64
	 */
	str_append(str, ",p=");
	base64_encode(client_proof, sizeof(client_proof), str);

	return str;
}

static int
auth_scram_parse_server_final(struct auth_scram_client *client,
			      const unsigned char *input, size_t input_len,
			      const char **error_r)
{
	const struct hash_method *hmethod = client->set.hash_method;
	const char **fields;
	unsigned int field_count;
	const char *error, *verifier;
	string_t *str;

	/* RFC 5802, Section 7:

	   server-final-message = (server-error / verifier)
	                     ["," extensions]
	 */

	fields = t_strsplit(t_strndup(input, input_len), ",");
	field_count = str_array_length(fields);
	if (field_count < 1) {
		*error_r = "Invalid final server message";
		return -1;
	}

	error = fields[0];
	verifier = fields[0];

	/* server-error = "e=" server-error-value
	 */
	if (error[0] == 'e' && error[1] == '=') {
		*error_r = t_strdup_printf("Server returned error value `%s'",
					   &error[2]);
		return -1;
	}

	/* verifier        = "v=" base64
	                     ;; base-64 encoded ServerSignature.
	 */
	if (verifier[0] != 'v' || verifier[1] != '=') {
		*error_r = "Invalid verifier field in final server message";
		return -1;
	}
	verifier += 2;

	i_assert(hmethod != NULL);
	i_assert(client->server_signature != NULL);
	str = t_str_new(MAX_BASE64_ENCODED_SIZE(hmethod->digest_size));
	base64_encode(client->server_signature, hmethod->digest_size, str);
	safe_memset(client->server_signature, 0, hmethod->digest_size);

	bool equal = str_equals_timing_almost_safe(verifier, str_c(str));
	str_clear_safe(str);

	if (!equal) {
		*error_r = "Incorrect verifier field in final server message";
		return -1;
	}
	return 0;
}

int auth_scram_client_input(struct auth_scram_client *client,
			    const unsigned char *input, size_t input_len,
			    const char **error_r)
{
	int ret = 0;

	switch (client->state) {
	case AUTH_SCRAM_CLIENT_STATE_INIT:
		break;
	case AUTH_SCRAM_CLIENT_STATE_CLIENT_FIRST:
		i_unreached();
	case AUTH_SCRAM_CLIENT_STATE_SERVER_FIRST:
		ret = auth_scram_parse_server_first(client, input, input_len,
						    error_r);
		break;
	case AUTH_SCRAM_CLIENT_STATE_CLIENT_FINAL:
		i_unreached();
	case AUTH_SCRAM_CLIENT_STATE_SERVER_FINAL:
		ret = auth_scram_parse_server_final(client, input, input_len,
						    error_r);
		break;
	case AUTH_SCRAM_CLIENT_STATE_CLIENT_FINISH:
		*error_r = "Server didn't finish authentication";
		ret = -1;
		break;
	case AUTH_SCRAM_CLIENT_STATE_END:
		i_unreached();
	}
	client->state++;

	return ret;
}

bool auth_scram_client_state_client_first(struct auth_scram_client *client)
{
	return (client->state <= AUTH_SCRAM_CLIENT_STATE_CLIENT_FIRST);
}

void auth_scram_client_output(struct auth_scram_client *client,
			      const unsigned char **output_r,
			      size_t *output_len_r)
{
	string_t *output;

	switch (client->state) {
	case AUTH_SCRAM_CLIENT_STATE_INIT:
		client->state = AUTH_SCRAM_CLIENT_STATE_CLIENT_FIRST;
		/* Fall through */
	case AUTH_SCRAM_CLIENT_STATE_CLIENT_FIRST:
		output = auth_scram_get_client_first(client);
		*output_r = str_data(output);
		*output_len_r = str_len(output);
		break;
	case AUTH_SCRAM_CLIENT_STATE_SERVER_FIRST:
		i_unreached();
	case AUTH_SCRAM_CLIENT_STATE_CLIENT_FINAL:
		output = auth_scram_get_client_final(client);
		*output_r = str_data(output);
		*output_len_r = str_len(output);
		break;
	case AUTH_SCRAM_CLIENT_STATE_SERVER_FINAL:
		i_unreached();
	case AUTH_SCRAM_CLIENT_STATE_CLIENT_FINISH:
		*output_r = uchar_empty_ptr;
		*output_len_r = 0;
		break;
	case AUTH_SCRAM_CLIENT_STATE_END:
		i_unreached();
	}
	client->state++;
}
