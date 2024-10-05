/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hex-binary.h"
#include "hmac.h"
#include "md5.h"

#include "dsasl-client-private.h"

struct cram_md5_dsasl_client {
	struct dsasl_client client;

	const char *challenge;
};

static enum dsasl_client_result
mech_cram_md5_input(struct dsasl_client *client,
		    const unsigned char *input, size_t input_len,
		    const char **error_r)
{
	struct cram_md5_dsasl_client *cclient =
		container_of(client, struct cram_md5_dsasl_client, client);

	const unsigned char *p = input, *pend = input + input_len;

	if (p >= pend) {
		*error_r = "Server sent empty challenge";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	if (*p != '<') {
		*error_r = "Server sent invalid challenge begin";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	p++;

	for (; (p + 1) < pend; p++) {
		if (*p <= 32 || *p == 127 || *p == '>') {
			*error_r = "Server sent invalid challenge";
			return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
		}
	}

	if (p >= pend || *p != '>') {
		*error_r = "Server sent invalid challenge end";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	p++;
	i_assert(p == pend);

	if (input_len < 5) {
		*error_r = "Server sent invalid challenge";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	cclient->challenge = p_strndup(client->pool, input, input_len);
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_cram_md5_output(struct dsasl_client *client,
		     const unsigned char **output_r, size_t *output_len_r,
		     const char **error_r)
{
	struct cram_md5_dsasl_client *cclient =
		container_of(client, struct cram_md5_dsasl_client, client);
	string_t *str;

	if (client->set.authid == NULL) {
		*error_r = "authid not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}
	if (client->password == NULL) {
		*error_r = "password not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}

	if (cclient->challenge == NULL) {
		*output_r = uchar_empty_ptr;
		*output_len_r = 0;
		return DSASL_CLIENT_RESULT_OK;
	}

	struct hmac_context ctx;
	unsigned char digest[MD5_RESULTLEN];

	hmac_init(&ctx, (const unsigned char *)client->password,
		  strlen(client->password), &hash_method_md5);
	hmac_update(&ctx, cclient->challenge, strlen(cclient->challenge));
	hmac_final(&ctx, digest);

	str = str_new(client->pool, 256);
	str_append(str, client->set.authid);
	str_append_c(str, ' ');
	binary_to_hex_append(str, digest, sizeof(digest));

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	return DSASL_CLIENT_RESULT_OK;
}

const struct dsasl_client_mech dsasl_client_mech_cram_md5 = {
	.name = SASL_MECH_NAME_CRAM_MD5,
	.struct_size = sizeof(struct cram_md5_dsasl_client),

	.input = mech_cram_md5_input,
	.output = mech_cram_md5_output,
};
