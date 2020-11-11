/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sha1.h"
#include "sha2.h"
#include "auth-scram-client.h"
#include "dsasl-client-private.h"

struct scram_dsasl_client {
	struct dsasl_client client;

	struct auth_scram_client scram_client;
};

static void mech_scram_init(struct scram_dsasl_client *sclient)
{
	struct dsasl_client *client = &sclient->client;
	const struct hash_method *hmethod;

	/* SCRAM-SHA-1 */
	if (client->mech == &dsasl_client_mech_scram_sha_1) {
		hmethod = &hash_method_sha1;
	/* SCRAM-SHA-256 */
	} else if (client->mech == &dsasl_client_mech_scram_sha_256) {
		hmethod = &hash_method_sha256;
	} else {
		i_unreached();
	}

	auth_scram_client_init(&sclient->scram_client, client->pool, hmethod,
			       client->set.authid, client->set.authzid,
			       client->password);
}

static int
mech_scram_input(struct dsasl_client *client,
		 const unsigned char *input, size_t input_len,
		 const char **error_r)
{
	struct scram_dsasl_client *sclient =
		container_of(client, struct scram_dsasl_client, client);

	if (sclient->scram_client.state == AUTH_SCRAM_CLIENT_STATE_INIT)
		mech_scram_init(sclient);

	return auth_scram_client_input(&sclient->scram_client,
				       input, input_len, error_r);
}

static int
mech_scram_output(struct dsasl_client *client,
		  const unsigned char **output_r, size_t *output_len_r,
		  const char **error_r)
{
	struct scram_dsasl_client *sclient =
		container_of(client, struct scram_dsasl_client, client);

	if (client->set.authid == NULL) {
		*error_r = "authid not set";
		return -1;
	}
	if (client->password == NULL) {
		*error_r = "password not set";
		return -1;
	}

	if (sclient->scram_client.state == AUTH_SCRAM_CLIENT_STATE_INIT)
		mech_scram_init(sclient);

	auth_scram_client_output(&sclient->scram_client,
				 output_r, output_len_r);
	return 0;
}

static void mech_scram_free(struct dsasl_client *client)
{
	struct scram_dsasl_client *sclient =
		container_of(client, struct scram_dsasl_client, client);

	auth_scram_client_deinit(&sclient->scram_client);
}

const struct dsasl_client_mech dsasl_client_mech_scram_sha_1 = {
	.name = "SCRAM-SHA-1",
	.struct_size = sizeof(struct scram_dsasl_client),

	.input = mech_scram_input,
	.output = mech_scram_output,
	.free = mech_scram_free,
};

const struct dsasl_client_mech dsasl_client_mech_scram_sha_256 = {
	.name = "SCRAM-SHA-256",
	.struct_size = sizeof(struct scram_dsasl_client),

	.input = mech_scram_input,
	.output = mech_scram_output,
	.free = mech_scram_free,
};
