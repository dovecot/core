/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"

#include "dsasl-client-protected.h"

struct plain_sasl_session {
	struct dsasl_client_mech_session session;

	bool output_sent;
};

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
		       const char **error_r)
{
	struct plain_sasl_session *psession =
		container_of(msession, struct plain_sasl_session, session);
	string_t *str;

	if (msession->set.authid == NULL || *msession->set.authid == '\0') {
		*error_r = "authid not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}
	if (msession->password == NULL) {
		*error_r = "password not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}

	str = str_new(msession->pool, 64);
	if (msession->set.authzid != NULL && *msession->set.authzid != '\0')
		str_append(str, msession->set.authzid);
	str_append_c(str, '\0');
	str_append(str, msession->set.authid);
	str_append_c(str, '\0');
	str_append(str, msession->password);

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	psession->output_sent = TRUE;
	return 0;
}

const struct dsasl_client_mech dsasl_client_mech_plain = {
	.name = SASL_MECH_NAME_PLAIN,
	.struct_size = sizeof(struct plain_sasl_session),

	.auth_input = mech_plain_auth_input,
	.auth_output = mech_plain_auth_output,
};
