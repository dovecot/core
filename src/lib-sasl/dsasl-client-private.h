#ifndef DSASL_CLIENT_PRIVATE_H
#define DSASL_CLIENT_PRIVATE_H

#include "dsasl-client.h"

enum dsasl_mech_security_flags {
	DSASL_MECH_SEC_ALLOW_NULS	= 0x0001,
};

struct dsasl_client {
	pool_t pool;
	struct dsasl_client_settings set;
	char *password;
	const struct dsasl_client_mech *mech;
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

extern const struct dsasl_client_mech dsasl_client_mech_external;
extern const struct dsasl_client_mech dsasl_client_mech_login;
extern const struct dsasl_client_mech dsasl_client_mech_oauthbearer;
extern const struct dsasl_client_mech dsasl_client_mech_xoauth2;

void dsasl_client_mech_register(const struct dsasl_client_mech *mech);
void dsasl_client_mech_unregister(const struct dsasl_client_mech *mech);

#endif
