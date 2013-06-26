/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "dsasl-client-private.h"

enum login_state {
	STATE_INIT = 0,
	STATE_USER,
	STATE_PASS
};

struct login_dsasl_client {
	struct dsasl_client client;
	enum login_state state;
};

static int
mech_login_input(struct dsasl_client *_client,
		 const unsigned char *input ATTR_UNUSED,
		 unsigned int input_len ATTR_UNUSED,
		 const char **error_r)
{
	struct login_dsasl_client *client =
		(struct login_dsasl_client *)_client;

	if (client->state == STATE_PASS) {
		*error_r = "Server didn't finish authentication";
		return -1;
	}
	client->state++;
	return 0;
}

static int
mech_login_output(struct dsasl_client *_client,
		  const unsigned char **output_r, unsigned int *output_len_r,
		  const char **error_r)
{
	struct login_dsasl_client *client =
		(struct login_dsasl_client *)_client;

	if (_client->set.authid == NULL) {
		*error_r = "authid not set";
		return -1;
	}
	if (_client->password == NULL) {
		*error_r = "password not set";
		return -1;
	}

	switch (client->state) {
	case STATE_INIT:
		*output_r = &uchar_nul;
		*output_len_r = 0;
		return 0;
	case STATE_USER:
		*output_r = (const unsigned char *)_client->set.authid;
		*output_len_r = strlen(_client->set.authid);
		return 0;
	case STATE_PASS:
		*output_r = (const unsigned char *)_client->set.password;
		*output_len_r = strlen(_client->set.password);
		return 0;
	}
	i_unreached();
}

const struct dsasl_client_mech dsasl_client_mech_login = {
	.name = "LOGIN",
	.struct_size = sizeof(struct login_dsasl_client),

	.input = mech_login_input,
	.output = mech_login_output
};
