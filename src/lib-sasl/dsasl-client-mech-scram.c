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
mech_scram_auth_check(struct dsasl_client_mech_session *msession,
		      const char **error_r)
{
	if (dsasl_client_session_check_authid(msession, error_r) < 0)
		return -1;
	if (dsasl_client_session_check_password(msession, error_r) < 0)
		return -1;
	return 0;
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

static enum auth_scram_cbind_server_support
mech_scram_get_cbind_server_support(
	struct scram_sasl_session *ssession,
	const struct dsasl_client_mech *mech,
	const struct dsasl_client_mech *plus_mech)
{
	struct dsasl_client_mech_session *msession = &ssession->session;
	int ret;

	if (mech == plus_mech) {
		/* Explicitly requested PLUS mechanism. This means the PLUS
		   mechanism is also explicitly listed by the server as a
		   capability or our configuration assumes support without
		   further checks.

		   RFC 5802, Section 6:

		   Conversely, if the client requires the use of channel binding
		   then it MUST use a "p" gs2-cbind-flag.

		   -> It does here

		   Clients that do not support mechanism negotiation never use a
		   "y" gs2-cbind-flag, they use either "p" or "n" according to
		   whether they require and support the use of channel binding
		   or whether they do not, respectively.

		   -> It always assumes channel binding support here
		*/
		return AUTH_SCRAM_CBIND_SERVER_SUPPORT_REQUIRED;
	}

	if (!dsasl_client_session_channel_binding_available(msession)) {
		/* If the client does not support channel binding, then it MUST
		   use an "n" gs2-cbind-flag. */
		return AUTH_SCRAM_CBIND_SERVER_SUPPORT_AVAILABLE;
	}

	/* RFC 5802, Section 6:

	   If the client supports channel binding and the server does not appear
	   to (i.e., the client did not see the -PLUS name advertised by the
	   server), then the client MUST NOT use an "n" gs2-cbind-flag.

	   -> Not possible in this code path
	 */

	ret = dsasl_client_session_server_supports_mech(msession,
							plus_mech->name);
	if (ret < 0)
		return AUTH_SCRAM_CBIND_SERVER_SUPPORT_AVAILABLE;
	if (ret == 0)
		return AUTH_SCRAM_CBIND_SERVER_SUPPORT_NONE;

	/*  RFC 5802, Section 6:

	    Clients that support mechanism negotiation and channel binding MUST
	    use a "p" gs2-cbind-flag when the server offers the PLUS-variant of
	    the desired GS2 mechanism.

	    -> So, even when the non-PLUS variant of the mechanism is
	       requested, act as though it was.
	 */
	return AUTH_SCRAM_CBIND_SERVER_SUPPORT_REQUIRED;
}

static int
mech_scram_init(struct scram_sasl_session *ssession, const char **error_r)
{
	struct dsasl_client_mech_session *msession = &ssession->session;
	const struct hash_method *hmethod;
	enum auth_scram_cbind_server_support cbind_support;

	/* Determine hash method */

	/* SCRAM-SHA-1 */
	if (msession->mech == &dsasl_client_mech_scram_sha_1)
		hmethod = &hash_method_sha1;
	/* SCRAM-SHA-1-PLUS */
	else if (msession->mech == &dsasl_client_mech_scram_sha_1_plus)
		hmethod = &hash_method_sha1;
	/* SCRAM-SHA-256 */
	else if (msession->mech == &dsasl_client_mech_scram_sha_256)
		hmethod = &hash_method_sha256;
	/* SCRAM-SHA-256-PLUS */
	else if (msession->mech == &dsasl_client_mech_scram_sha_256_plus)
		hmethod = &hash_method_sha256;
	else
		i_unreached();

	/* Determine level of server channel binding support we're assuming. */

	/* SCRAM-SHA-1* */
	if (hmethod == &hash_method_sha1) {
		cbind_support = mech_scram_get_cbind_server_support(
			ssession, msession->mech,
			&dsasl_client_mech_scram_sha_1_plus);
	/* SCRAM-SHA-256* */
	} else if (hmethod == &hash_method_sha256) {
		cbind_support = mech_scram_get_cbind_server_support(
			ssession, msession->mech,
			&dsasl_client_mech_scram_sha_256_plus);
	} else
		i_unreached();

	/* Initialize channel binding when required */

	if (cbind_support == AUTH_SCRAM_CBIND_SERVER_SUPPORT_REQUIRED &&
	    mech_scram_init_channel_binding(ssession, error_r) < 0)
		return -1;

	struct auth_scram_client_settings scram_set;

	i_zero(&scram_set);
	scram_set.hash_method = hmethod;
	scram_set.authid = msession->authid;
	scram_set.authzid = msession->authzid;
	scram_set.password = msession->password;
	scram_set.cbind_support = cbind_support;
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
	.auth_check = mech_scram_auth_check,
	.auth_input = mech_scram_auth_input,
	.auth_output = mech_scram_auth_output,
};

const struct dsasl_client_mech dsasl_client_mech_scram_sha_1_plus = {
	.name = SASL_MECH_NAME_SCRAM_SHA_1_PLUS,

	.auth_new = mech_scram_auth_new,
	.auth_free = mech_scram_auth_free,
	.auth_check = mech_scram_auth_check,
	.auth_input = mech_scram_auth_input,
	.auth_output = mech_scram_auth_output,
};

const struct dsasl_client_mech dsasl_client_mech_scram_sha_256 = {
	.name = SASL_MECH_NAME_SCRAM_SHA_256,

	.auth_new = mech_scram_auth_new,
	.auth_free = mech_scram_auth_free,
	.auth_check = mech_scram_auth_check,
	.auth_input = mech_scram_auth_input,
	.auth_output = mech_scram_auth_output,
};

const struct dsasl_client_mech dsasl_client_mech_scram_sha_256_plus = {
	.name = SASL_MECH_NAME_SCRAM_SHA_256_PLUS,

	.auth_new = mech_scram_auth_new,
	.auth_free = mech_scram_auth_free,
	.auth_check = mech_scram_auth_check,
	.auth_input = mech_scram_auth_input,
	.auth_output = mech_scram_auth_output,
};
