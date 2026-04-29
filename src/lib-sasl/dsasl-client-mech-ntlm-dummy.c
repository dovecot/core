/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"

#include "dsasl-client-protected.h"
#include "dsasl-client-mech-ntlm-dummy.h"

/* Dummy NTLM mechanism

   This has nothing to do with actual NTLM; it just serves as a means to test
   the winbind server mechanisms.
 */

enum ntlm_state {
	STATE_INIT = 0,
	STATE_RESPONSE
};

struct ntlm_sasl_session {
	struct dsasl_client_mech_session session;

	enum ntlm_state state;
};

void dasl_client_mech_ntlm_init_dummy(void);

static struct dsasl_client_mech_session *mech_ntlm_auth_new(pool_t pool)
{
	struct ntlm_sasl_session *nsession =
		p_new(pool, struct ntlm_sasl_session, 1);
	return &nsession->session;
}

static int
mech_ntlm_auth_check(struct dsasl_client_mech_session *msession,
		     const char **error_r)
{
	if (msession->authid == NULL) {
		*error_r = "authid not set";
		return -1;
	}
	if (msession->password == NULL) {
		*error_r = "password not set";
		return -1;
	}
	return 0;
}

static enum dsasl_client_result
mech_ntlm_auth_input(struct dsasl_client_mech_session *msession,
		     const unsigned char *input, size_t input_len,
		     const char **error_r)
{
	static const char *challenge = "Challenge";
	struct ntlm_sasl_session *nsession =
		container_of(msession, struct ntlm_sasl_session, session);
	size_t chal_size;

	if (nsession->state == STATE_RESPONSE) {
		*error_r = "Server didn't finish authentication";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	chal_size = strlen(challenge);
	if (input_len != chal_size ||
	    memcmp(input, challenge, chal_size) != 0) {
		*error_r = "Invalid challenge";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	nsession->state++;
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_ntlm_auth_output(struct dsasl_client_mech_session *msession,
		      const unsigned char **output_r, size_t *output_len_r,
		      const char **error_r ATTR_UNUSED)
{
	struct ntlm_sasl_session *nsession =
		container_of(msession, struct ntlm_sasl_session, session);
	const char *response;

	switch (nsession->state) {
	case STATE_INIT:
		*output_r = uchar_empty_ptr;
		*output_len_r = 0;
		return DSASL_CLIENT_RESULT_OK;
	case STATE_RESPONSE:
		response = t_strconcat("Response: ",
				       msession->authid, NULL);
		*output_r = (const unsigned char *)response;
		*output_len_r = strlen(response);
		return DSASL_CLIENT_RESULT_OK;
	}
	i_unreached();
}

const struct dsasl_client_mech dsasl_client_mech_ntlm = {
	.name = SASL_MECH_NAME_NTLM,

	.auth_new = mech_ntlm_auth_new,
	.auth_check = mech_ntlm_auth_check,
	.auth_input = mech_ntlm_auth_input,
	.auth_output = mech_ntlm_auth_output,
};

void dsasl_client_init_ntlm_dummy(struct dsasl_client *client)
{
	dsasl_client_mech_register(client, &dsasl_client_mech_ntlm);
}
