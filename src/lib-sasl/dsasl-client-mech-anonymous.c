/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"

#include "dsasl-client-protected.h"

struct anonymous_sasl_session {
	struct dsasl_client_mech_session session;

	bool output_sent;
};

static enum dsasl_client_result
mech_anonymous_input(struct dsasl_client_mech_session *msession,
		     const unsigned char *input ATTR_UNUSED, size_t input_len,
		     const char **error_r)
{
	struct anonymous_sasl_session *asession =
		container_of(msession, struct anonymous_sasl_session, session);

	if (!asession->output_sent) {
		if (input_len > 0) {
			*error_r = "Server sent non-empty initial response";
			return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
		}
	} else if (input_len > 0) {
		*error_r = "Server sent non-empty response";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_anonymous_output(struct dsasl_client_mech_session *msession,
		      const unsigned char **output_r, size_t *output_len_r,
		      const char **error_r ATTR_UNUSED)
{
	struct anonymous_sasl_session *asession =
		container_of(msession, struct anonymous_sasl_session, session);

	const char *authid = msession->set.authid;
	if (authid == NULL)
		authid = "";
	*output_r = (const unsigned char*)authid;
	*output_len_r = strlen(authid);
	asession->output_sent = TRUE;
	return DSASL_CLIENT_RESULT_OK;
}

const struct dsasl_client_mech dsasl_client_mech_anonymous = {
	.name = SASL_MECH_NAME_ANONYMOUS,
	.struct_size = sizeof(struct anonymous_sasl_session),
	.flags = DSASL_MECH_SEC_NO_PASSWORD,

	.input = mech_anonymous_input,
	.output = mech_anonymous_output
};
