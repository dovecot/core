/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "dsasl-client-private.h"

struct external_sasl_session {
	struct dsasl_client_mech_session session;

	bool output_sent;
};

static enum dsasl_client_result
mech_external_input(struct dsasl_client_mech_session *msession,
		    const unsigned char *input ATTR_UNUSED, size_t input_len,
		    const char **error_r)
{
	struct external_sasl_session *esession =
		container_of(msession, struct external_sasl_session, session);

	if (!esession->output_sent) {
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
mech_external_output(struct dsasl_client_mech_session *msession,
		     const unsigned char **output_r, size_t *output_len_r,
		     const char **error_r ATTR_UNUSED)
{
	struct external_sasl_session *esession =
		container_of(msession, struct external_sasl_session, session);
	const char *username;

	if (msession->set.authzid != NULL && *msession->set.authzid != '\0')
		username = msession->set.authzid;
	else if (msession->set.authid != NULL && *msession->set.authid != '\0')
		username = msession->set.authid;
	else
		username = "";

	*output_r = (const void *)username;
	*output_len_r = strlen(username);
	esession->output_sent = TRUE;
	return DSASL_CLIENT_RESULT_OK;
}

const struct dsasl_client_mech dsasl_client_mech_external = {
	.name = SASL_MECH_NAME_EXTERNAL,
	.struct_size = sizeof(struct external_sasl_session),
	.flags = DSASL_MECH_SEC_NO_PASSWORD,

	.input = mech_external_input,
	.output = mech_external_output
};
