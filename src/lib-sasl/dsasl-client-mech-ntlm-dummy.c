/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dsasl-client-private.h"
#include "dsasl-client-mech-ntlm-dummy.h"

/* Dummy NTLM mechanism

   This has nothing to do with actual NTLM; it just serves as a means to test
   the winbind server mechanisms.
 */

enum ntlm_state {
	STATE_INIT = 0,
	STATE_RESPONSE
};

struct ntlm_dsasl_client {
	struct dsasl_client client;
	enum ntlm_state state;
};

void dasl_client_mech_ntlm_init_dummy(void);

static enum dsasl_client_result
mech_ntlm_input(struct dsasl_client *_client,
		const unsigned char *input, size_t input_len,
		const char **error_r)
{
	static const char *challenge = "Challenge";
	struct ntlm_dsasl_client *client =
		container_of(_client, struct ntlm_dsasl_client, client);
	size_t chal_size;

	if (client->state == STATE_RESPONSE) {
		*error_r = "Server didn't finish authentication";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	chal_size = strlen(challenge);
	if (input_len != chal_size ||
	    memcmp(input, challenge, chal_size) != 0) {
		*error_r = "Invalid challenge";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	client->state++;
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_ntlm_output(struct dsasl_client *_client,
		  const unsigned char **output_r, size_t *output_len_r,
		  const char **error_r)
{
	struct ntlm_dsasl_client *client =
		container_of(_client, struct ntlm_dsasl_client, client);

	if (_client->set.authid == NULL) {
		*error_r = "authid not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}
	if (_client->password == NULL) {
		*error_r = "password not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}

	const char *response;

	switch (client->state) {
	case STATE_INIT:
		*output_r = uchar_empty_ptr;
		*output_len_r = 0;
		return DSASL_CLIENT_RESULT_OK;
	case STATE_RESPONSE:
		response = t_strconcat("Response: ", _client->set.authid, NULL);
		*output_r = (const unsigned char *)response;
		*output_len_r = strlen(response);
		return DSASL_CLIENT_RESULT_OK;
	}
	i_unreached();
}

const struct dsasl_client_mech dsasl_client_mech_ntlm = {
	.name = SASL_MECH_NAME_NTLM,
	.struct_size = sizeof(struct ntlm_dsasl_client),

	.input = mech_ntlm_input,
	.output = mech_ntlm_output
};

void dsasl_client_mech_ntlm_init_dummy(void)
{
	dsasl_client_mech_register(&dsasl_client_mech_ntlm);
}
