/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "hex-binary.h"
#include "hmac.h"
#include "md5.h"

#include "dsasl-client-protected.h"

struct cram_md5_sasl_session {
	struct dsasl_client_mech_session session;

	const char *challenge;
};

static struct dsasl_client_mech_session *mech_cram_md5_auth_new(pool_t pool)
{
	struct cram_md5_sasl_session *csession =
		p_new(pool, struct cram_md5_sasl_session, 1);
	return &csession->session;
}

static int
mech_cram_md5_auth_check(struct dsasl_client_mech_session *msession,
			 const char **error_r)
{
	if (dsasl_client_session_check_authid(msession, error_r) < 0)
		return -1;
	if (dsasl_client_session_check_password(msession, error_r) < 0)
		return -1;
	return 0;
}

static enum dsasl_client_result
mech_cram_md5_auth_input(struct dsasl_client_mech_session *msession,
			 const unsigned char *input, size_t input_len,
			 const char **error_r)
{
	struct cram_md5_sasl_session *csession =
		container_of(msession, struct cram_md5_sasl_session, session);
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

	csession->challenge = p_strndup(msession->pool, input, input_len);
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_cram_md5_auth_output(struct dsasl_client_mech_session *msession,
			  const unsigned char **output_r, size_t *output_len_r,
			  const char **error_r ATTR_UNUSED)
{
	struct cram_md5_sasl_session *csession =
		container_of(msession, struct cram_md5_sasl_session, session);
	string_t *str;

	if (csession->challenge == NULL) {
		*output_r = NULL;
		*output_len_r = 0;
		return DSASL_CLIENT_RESULT_OK;
	}

	struct hmac_context ctx;
	unsigned char digest[MD5_RESULTLEN];

	hmac_init(&ctx, (const unsigned char *)msession->password,
		  strlen(msession->password), &hash_method_md5);
	hmac_update(&ctx, csession->challenge, strlen(csession->challenge));
	hmac_final(&ctx, digest);

	str = str_new(msession->pool, 256);
	str_append(str, msession->authid);
	str_append_c(str, ' ');
	binary_to_hex_append(str, digest, sizeof(digest));

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	return DSASL_CLIENT_RESULT_OK;
}

const struct dsasl_client_mech dsasl_client_mech_cram_md5 = {
	.name = SASL_MECH_NAME_CRAM_MD5,

	.auth_new = mech_cram_md5_auth_new,
	.auth_check = mech_cram_md5_auth_check,
	.auth_input = mech_cram_md5_auth_input,
	.auth_output = mech_cram_md5_auth_output,
};
