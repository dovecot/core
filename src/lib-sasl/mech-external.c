/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dsasl-client-private.h"

struct external_dsasl_client {
	struct dsasl_client client;
	bool output_sent;
};

static int
mech_external_input(struct dsasl_client *_client,
		    const unsigned char *input ATTR_UNUSED, unsigned int input_len,
		    const char **error_r)
{
	struct external_dsasl_client *client =
		(struct external_dsasl_client *)_client;

	if (!client->output_sent) {
		if (input_len > 0) {
			*error_r = "Server sent non-empty initial response";
			return -1;
		}
	} else {
		*error_r = "Server didn't finish authentication";
		return -1;
	}
	return 0;
}

static int
mech_external_output(struct dsasl_client *_client,
		     const unsigned char **output_r, unsigned int *output_len_r,
		     const char **error_r ATTR_UNUSED)
{
	struct external_dsasl_client *client =
		(struct external_dsasl_client *)_client;
	const char *username;

	if (_client->set.authzid != NULL)
		username = _client->set.authzid;
	else if (_client->set.authid != NULL)
		username = _client->set.authid;
	else
		username = "";

	*output_r = (const void *)username;
	*output_len_r = strlen(username);
	client->output_sent = TRUE;
	return 0;
}

const struct dsasl_client_mech dsasl_client_mech_external = {
	.name = "EXTERNAL",
	.struct_size = sizeof(struct external_dsasl_client),

	.input = mech_external_input,
	.output = mech_external_output
};
