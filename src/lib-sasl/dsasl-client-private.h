#ifndef DSASL_CLIENT_PRIVATE_H
#define DSASL_CLIENT_PRIVATE_H

#include "dsasl-client.h"

enum dsasl_mech_security_flags {
	DSASL_MECH_SEC_ALLOW_NULS	= BIT(1),
	DSASL_MECH_SEC_NO_PASSWORD	= BIT(2),
};

struct dsasl_client {
	pool_t pool;
	struct dsasl_client_settings set;
	char *password;
	const struct dsasl_client_mech *mech;

	enum ssl_iostream_protocol_version channel_version;
	dsasl_client_channel_binding_callback_t *cbinding_callback;
	void *cbinding_context;
};

struct dsasl_client_mech {
	const char *name;
	size_t struct_size;
	enum dsasl_mech_security_flags flags;

	int (*input)(struct dsasl_client *client,
		     const unsigned char *input, size_t input_len,
		     const char **error_r);
	int (*output)(struct dsasl_client *client,
		      const unsigned char **output_r, size_t *output_len_r,
		      const char **error_r);
	int (*set_parameter)(struct dsasl_client *client,
			     const char *key, const char *value,
			     const char **error_r);
	int (*get_result)(struct dsasl_client *client,
			  const char *key, const char **value_r,
			  const char **error_r);
	void (*free)(struct dsasl_client *client);
};

extern const struct dsasl_client_mech dsasl_client_mech_anonymous;
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

static inline int
dasl_client_get_channel_binding(struct dsasl_client *client,
				const char *type, const buffer_t **data_r,
				const char **error_r)
{
	if (client->channel_version == SSL_IOSTREAM_PROTOCOL_VERSION_UNKNOWN ||
	    client->cbinding_callback == NULL) {
		*error_r = "Channel binding not available locally";
		return -1;
	}
	return client->cbinding_callback(type, client->cbinding_context,
					 data_r, error_r);
}

#endif
