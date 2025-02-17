/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dsasl-client-private.h"

struct anonymous_dsasl_client {
	struct dsasl_client client;
	bool output_sent;
};

static int
mech_anonymous_input(struct dsasl_client *_client,
		    const unsigned char *input ATTR_UNUSED, size_t input_len,
		    const char **error_r)
{
	struct anonymous_dsasl_client *client =
		container_of(_client, struct anonymous_dsasl_client, client);

	if (!client->output_sent) {
		if (input_len > 0) {
			*error_r = "Server sent non-empty initial response";
			return -1;
		}
	} else if (input_len > 0) {
		*error_r = "Server sent non-empty response";
		return -1;
	}
	return 0;
}

static int
mech_anonymous_output(struct dsasl_client *_client,
		     const unsigned char **output_r, size_t *output_len_r,
		     const char **error_r ATTR_UNUSED)
{
	struct anonymous_dsasl_client *client =
		container_of(_client, struct anonymous_dsasl_client, client);

	const char *authid = client->client.set.authid;
	if (authid == NULL)
		authid = "";
	*output_r = (const unsigned char*)authid;
	*output_len_r = strlen(authid);
	client->output_sent = TRUE;
	return 0;
}

const struct dsasl_client_mech dsasl_client_mech_anonymous = {
	.name = "ANONYMOUS",
	.struct_size = sizeof(struct anonymous_dsasl_client),
	.flags = DSASL_MECH_SEC_NO_PASSWORD,

	.input = mech_anonymous_input,
	.output = mech_anonymous_output
};
