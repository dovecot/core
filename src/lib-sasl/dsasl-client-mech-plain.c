/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"

#include "dsasl-client-protected.h"

struct plain_sasl_session {
	struct dsasl_client_mech_session session;

	bool output_sent;
};

static struct dsasl_client_mech_session *mech_plain_auth_new(pool_t pool)
{
	struct plain_sasl_session *psession =
		p_new(pool, struct plain_sasl_session, 1);
	return &psession->session;
}

static int
mech_plain_auth_check(struct dsasl_client_mech_session *msession,
		      const char **error_r)
{
	if (dsasl_client_session_check_authid(msession, error_r) < 0)
		return -1;
	if (dsasl_client_session_check_password(msession, error_r) < 0)
		return -1;
	return 0;
}

static enum dsasl_client_result
mech_plain_auth_input(struct dsasl_client_mech_session *msession,
		      const unsigned char *input ATTR_UNUSED, size_t input_len,
		      const char **error_r)
{
	struct plain_sasl_session *psession =
		container_of(msession, struct plain_sasl_session, session);

	if (!psession->output_sent) {
		if (input_len > 0) {
			*error_r = "Server sent non-empty initial response";
			return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
		}
	} else {
		*error_r = "Server didn't finish authentication";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_plain_auth_output(struct dsasl_client_mech_session *msession,
		       const unsigned char **output_r, size_t *output_len_r,
		       const char **error_r ATTR_UNUSED)
{
	struct plain_sasl_session *psession =
		container_of(msession, struct plain_sasl_session, session);
	string_t *str;

	str = str_new(msession->pool, 64);
	if (msession->authzid != NULL)
		str_append(str, msession->authzid);
	str_append_c(str, '\0');
	str_append(str, msession->authid);
	str_append_c(str, '\0');
	str_append(str, msession->password);

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	psession->output_sent = TRUE;
	return 0;
}

const struct dsasl_client_mech dsasl_client_mech_plain = {
	.name = SASL_MECH_NAME_PLAIN,

	.auth_new = mech_plain_auth_new,
	.auth_check = mech_plain_auth_check,
	.auth_input = mech_plain_auth_input,
	.auth_output = mech_plain_auth_output,
};
