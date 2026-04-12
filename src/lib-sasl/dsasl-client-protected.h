#ifndef DSASL_CLIENT_PROTECTED_H
#define DSASL_CLIENT_PROTECTED_H

#include "sasl-common.h"
#include "dsasl-client.h"

struct dsasl_client_mech_session;

enum dsasl_mech_security_flags {
	DSASL_MECH_SEC_ALLOW_NULS	= BIT(1),
	DSASL_MECH_SEC_NO_PASSWORD	= BIT(2),
};

struct dsasl_client_mech {
	const char *name;
	size_t struct_size;
	enum dsasl_mech_security_flags flags;

	enum dsasl_client_result
	(*auth_input)(struct dsasl_client_mech_session *msession,
		      const unsigned char *input, size_t input_len,
		      const char **error_r);
	enum dsasl_client_result
	(*auth_output)(struct dsasl_client_mech_session *msession,
		       const unsigned char **output_r, size_t *output_len_r,
		       const char **error_r);
	int (*auth_get_result)(struct dsasl_client_mech_session *msession,
			       const char *key, const char **value_r,
			       const char **error_r);
	void (*auth_free)(struct dsasl_client_mech_session *msession);
};

struct dsasl_client_mech_session {
	pool_t pool;
	struct event *event;
	const struct dsasl_client_mech *mech;
	struct dsasl_client_settings set;
	struct dsasl_client_session *session;

	char *password;

	enum ssl_iostream_protocol_version channel_version;
};

/*
 * Mechanism
 */

extern const struct dsasl_client_mech dsasl_client_mech_anonymous;
extern const struct dsasl_client_mech dsasl_client_mech_cram_md5;
extern const struct dsasl_client_mech dsasl_client_mech_digest_md5;
extern const struct dsasl_client_mech dsasl_client_mech_external;
extern const struct dsasl_client_mech dsasl_client_mech_login;
extern const struct dsasl_client_mech dsasl_client_mech_oauthbearer;
extern const struct dsasl_client_mech dsasl_client_mech_xoauth2;
extern const struct dsasl_client_mech dsasl_client_mech_scram_sha_1;
extern const struct dsasl_client_mech dsasl_client_mech_scram_sha_1_plus;
extern const struct dsasl_client_mech dsasl_client_mech_scram_sha_256;
extern const struct dsasl_client_mech dsasl_client_mech_scram_sha_256_plus;

void dsasl_client_mech_register(const struct dsasl_client_mech *mech);
void dsasl_client_mech_unregister(const struct dsasl_client_mech *mech);

/*
 * Session
 */

int dsasl_client_session_get_channel_binding(
	struct dsasl_client_mech_session *msession, const char *type,
	const buffer_t **data_r, const char **error_r);

#endif
