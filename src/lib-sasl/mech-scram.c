/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sha1.h"
#include "sha2.h"
#include "auth-scram-client.h"
#include "dsasl-client-private.h"

struct scram_dsasl_client {
	struct dsasl_client client;

	const char *cbind_type;
	const buffer_t *cbind_data;
	struct auth_scram_client scram_client;
};

static int
mech_scram_init_channel_binding(struct scram_dsasl_client *sclient,
				const char **error_r)
{
	struct dsasl_client *client = &sclient->client;
	const char *type;
	const buffer_t *cbind_data;

	if (client->channel_version >= SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_3)
		type = SSL_CHANNEL_BIND_TYPE_TLS_EXPORTER;
	else
		type = SSL_CHANNEL_BIND_TYPE_TLS_UNIQUE;

	if (dasl_client_get_channel_binding(client, type,
					    &cbind_data, error_r) < 0)
		return -1;

	sclient->cbind_type = type;
	sclient->cbind_data = buffer_clone(client->pool, cbind_data, 0);
	return 0;
}

static int mech_scram_init(struct scram_dsasl_client *sclient,
			   const char **error_r)
{
	struct dsasl_client *client = &sclient->client;
	const struct hash_method *hmethod;
	bool cbind = FALSE;

	/* SCRAM-SHA-1 */
	if (client->mech == &dsasl_client_mech_scram_sha_1) {
		hmethod = &hash_method_sha1;
	/* SCRAM-SHA-1-PLUS */
	} else if (client->mech == &dsasl_client_mech_scram_sha_1_plus) {
		hmethod = &hash_method_sha1;
		cbind = TRUE;
	/* SCRAM-SHA-256 */
	} else if (client->mech == &dsasl_client_mech_scram_sha_256) {
		hmethod = &hash_method_sha256;
	/* SCRAM-SHA-256-PLUS */
	} else if (client->mech == &dsasl_client_mech_scram_sha_256_plus) {
		hmethod = &hash_method_sha256;
		cbind = TRUE;
	} else {
		i_unreached();
	}

	/* FIXME: We should determine server support for -PLUS mechanisms
	   explicitly and always initialize channel binding, so that the correct
	   p=,y,n gs2-header is sent. This is only possible when the SASL client
	   has access to the list of mechanisms announced by the server, which
	   is currently not available. */
	if (cbind && mech_scram_init_channel_binding(sclient, error_r) < 0)
		return -1;

	struct auth_scram_client_settings scram_set;

	i_zero(&scram_set);
	scram_set.hash_method = hmethod;
	scram_set.authid = client->set.authid;
	scram_set.authzid = client->set.authzid;
	scram_set.password = client->password;
	scram_set.cbind_support = (cbind ? // FIXME: See above.
				   AUTH_SCRAM_CBIND_SERVER_SUPPORT_REQUIRED :
				   AUTH_SCRAM_CBIND_SERVER_SUPPORT_NONE);
	scram_set.cbind_type = sclient->cbind_type;
	scram_set.cbind_data = sclient->cbind_data;

	auth_scram_client_init(&sclient->scram_client, client->pool,
			       &scram_set);
	return 0;
}

static int
mech_scram_input(struct dsasl_client *client,
		 const unsigned char *input, size_t input_len,
		 const char **error_r)
{
	struct scram_dsasl_client *sclient =
		container_of(client, struct scram_dsasl_client, client);

	if (sclient->scram_client.state == AUTH_SCRAM_CLIENT_STATE_INIT &&
	    mech_scram_init(sclient, error_r) < 0)
		return -1;

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

	*output_r = NULL;
	*output_len_r = 0;

	if (client->set.authid == NULL) {
		*error_r = "authid not set";
		return -1;
	}
	if (client->password == NULL) {
		*error_r = "password not set";
		return -1;
	}

	if (sclient->scram_client.state == AUTH_SCRAM_CLIENT_STATE_INIT &&
	    mech_scram_init(sclient, error_r) < 0)
		return -1;

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

const struct dsasl_client_mech dsasl_client_mech_scram_sha_1_plus = {
	.name = "SCRAM-SHA-1-PLUS",
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

const struct dsasl_client_mech dsasl_client_mech_scram_sha_256_plus = {
	.name = "SCRAM-SHA-256-PLUS",
	.struct_size = sizeof(struct scram_dsasl_client),

	.input = mech_scram_input,
	.output = mech_scram_output,
	.free = mech_scram_free,
};
