/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "sha1.h"
#include "sha2.h"
#include "auth-scram-client.h"

#include "dsasl-client-protected.h"

struct scram_sasl_session {
	struct dsasl_client_mech_session session;

	const char *cbind_type;
	const buffer_t *cbind_data;
	struct auth_scram_client scram_client;
};

static struct dsasl_client_mech_session *mech_scram_auth_new(pool_t pool)
{
	struct scram_sasl_session *ssession =
		p_new(pool, struct scram_sasl_session, 1);
	return &ssession->session;
}

static void mech_scram_auth_free(struct dsasl_client_mech_session *msession)
{
	struct scram_sasl_session *ssession =
		container_of(msession, struct scram_sasl_session, session);

	auth_scram_client_deinit(&ssession->scram_client);
}

static int
mech_scram_init_channel_binding(struct scram_sasl_session *ssession,
				const char **error_r)
{
	struct dsasl_client_mech_session *msession = &ssession->session;
	const char *type;
	const buffer_t *cbind_data;

	if (msession->channel_version >= SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_3)
		type = SSL_CHANNEL_BIND_TYPE_TLS_EXPORTER;
	else
		type = SSL_CHANNEL_BIND_TYPE_TLS_UNIQUE;

	if (dsasl_client_session_get_channel_binding(msession, type,
						     &cbind_data, error_r) < 0)
		return -1;

	ssession->cbind_type = type;
	ssession->cbind_data = buffer_clone(msession->pool, cbind_data, 0);
	return 0;
}

static int
mech_scram_init(struct scram_sasl_session *ssession, const char **error_r)
{
	struct dsasl_client_mech_session *msession = &ssession->session;
	const struct hash_method *hmethod;
	bool cbind = FALSE;

	/* SCRAM-SHA-1 */
	if (msession->mech == &dsasl_client_mech_scram_sha_1) {
		hmethod = &hash_method_sha1;
	/* SCRAM-SHA-1-PLUS */
	} else if (msession->mech == &dsasl_client_mech_scram_sha_1_plus) {
		hmethod = &hash_method_sha1;
		cbind = TRUE;
	/* SCRAM-SHA-256 */
	} else if (msession->mech == &dsasl_client_mech_scram_sha_256) {
		hmethod = &hash_method_sha256;
	/* SCRAM-SHA-256-PLUS */
	} else if (msession->mech == &dsasl_client_mech_scram_sha_256_plus) {
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
	if (cbind && mech_scram_init_channel_binding(ssession, error_r) < 0)
		return -1;

	struct auth_scram_client_settings scram_set;

	i_zero(&scram_set);
	scram_set.hash_method = hmethod;
	scram_set.authid = msession->set.authid;
	scram_set.authzid = msession->set.authzid;
	scram_set.password = msession->password;
	scram_set.cbind_support = (cbind ? // FIXME: See above.
				   AUTH_SCRAM_CBIND_SERVER_SUPPORT_REQUIRED :
				   AUTH_SCRAM_CBIND_SERVER_SUPPORT_NONE);
	scram_set.cbind_type = ssession->cbind_type;
	scram_set.cbind_data = ssession->cbind_data;

	auth_scram_client_init(&ssession->scram_client, msession->pool,
			       &scram_set);
	return 0;
}

static enum dsasl_client_result
mech_scram_auth_input(struct dsasl_client_mech_session *msession,
		      const unsigned char *input, size_t input_len,
		      const char **error_r)
{
	struct scram_sasl_session *ssession =
		container_of(msession, struct scram_sasl_session, session);

	if (ssession->scram_client.state == AUTH_SCRAM_CLIENT_STATE_INIT &&
	    mech_scram_init(ssession, error_r) < 0)
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;

	if (auth_scram_client_input(&ssession->scram_client,
				    input, input_len, error_r) < 0)
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	return 0;
}

static enum dsasl_client_result
mech_scram_auth_output(struct dsasl_client_mech_session *msession,
		       const unsigned char **output_r, size_t *output_len_r,
		       const char **error_r)
{
	struct scram_sasl_session *ssession =
		container_of(msession, struct scram_sasl_session, session);

	*output_r = NULL;
	*output_len_r = 0;

	if (msession->set.authid == NULL || *msession->set.authid == '\0') {
		*error_r = "authid not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}
	if (msession->password == NULL) {
		*error_r = "password not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}

	if (ssession->scram_client.state == AUTH_SCRAM_CLIENT_STATE_INIT &&
	    mech_scram_init(ssession, error_r) < 0)
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;

	auth_scram_client_output(&ssession->scram_client,
				 output_r, output_len_r);
	return DSASL_CLIENT_RESULT_OK;
}

const struct dsasl_client_mech dsasl_client_mech_scram_sha_1 = {
	.name = SASL_MECH_NAME_SCRAM_SHA_1,

	.auth_new = mech_scram_auth_new,
	.auth_free = mech_scram_auth_free,
	.auth_input = mech_scram_auth_input,
	.auth_output = mech_scram_auth_output,
};

const struct dsasl_client_mech dsasl_client_mech_scram_sha_1_plus = {
	.name = SASL_MECH_NAME_SCRAM_SHA_1_PLUS,

	.auth_new = mech_scram_auth_new,
	.auth_free = mech_scram_auth_free,
	.auth_input = mech_scram_auth_input,
	.auth_output = mech_scram_auth_output,
};

const struct dsasl_client_mech dsasl_client_mech_scram_sha_256 = {
	.name = SASL_MECH_NAME_SCRAM_SHA_256,

	.auth_new = mech_scram_auth_new,
	.auth_free = mech_scram_auth_free,
	.auth_input = mech_scram_auth_input,
	.auth_output = mech_scram_auth_output,
};

const struct dsasl_client_mech dsasl_client_mech_scram_sha_256_plus = {
	.name = SASL_MECH_NAME_SCRAM_SHA_256_PLUS,

	.auth_new = mech_scram_auth_new,
	.auth_free = mech_scram_auth_free,
	.auth_input = mech_scram_auth_input,
	.auth_output = mech_scram_auth_output,
};
