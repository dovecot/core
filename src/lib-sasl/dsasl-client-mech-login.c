/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"

#include "dsasl-client-protected.h"

enum login_state {
	STATE_INIT = 0,
	STATE_USER,
	STATE_PASS
};

struct login_sasl_session {
	struct dsasl_client_mech_session session;

	enum login_state state;
};

static enum dsasl_client_result
mech_login_auth_input(struct dsasl_client_mech_session *msession,
		      const unsigned char *input ATTR_UNUSED,
		      size_t input_len ATTR_UNUSED, const char **error_r)
{
	struct login_sasl_session *lsession =
		container_of(msession, struct login_sasl_session, session);

	if (lsession->state == STATE_PASS) {
		*error_r = "Server didn't finish authentication";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	lsession->state++;
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_login_auth_output(struct dsasl_client_mech_session *msession,
		       const unsigned char **output_r, size_t *output_len_r,
		       const char **error_r)
{
	struct login_sasl_session *lsession =
		container_of(msession, struct login_sasl_session, session);

	if (msession->set.authid == NULL || *msession->set.authid == '\0') {
		*error_r = "authid not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}
	if (msession->password == NULL) {
		*error_r = "password not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}

	switch (lsession->state) {
	case STATE_INIT:
		*output_r = NULL;
		*output_len_r = 0;
		return DSASL_CLIENT_RESULT_OK;
	case STATE_USER:
		*output_r = (const unsigned char *)msession->set.authid;
		*output_len_r = strlen(msession->set.authid);
		return DSASL_CLIENT_RESULT_OK;
	case STATE_PASS:
		*output_r = (const unsigned char *)msession->set.password;
		*output_len_r = strlen(msession->set.password);
		return DSASL_CLIENT_RESULT_OK;
	}
	i_unreached();
}

const struct dsasl_client_mech dsasl_client_mech_login = {
	.name = SASL_MECH_NAME_LOGIN,
	.struct_size = sizeof(struct login_sasl_session),

	.auth_input = mech_login_auth_input,
	.auth_output = mech_login_auth_output,
};
