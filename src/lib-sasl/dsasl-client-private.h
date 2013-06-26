#ifndef DSASL_CLIENT_PRIVATE_H
#define DSASL_CLIENT_PRIVATE_H

#include "dsasl-client.h"

struct dsasl_client {
	pool_t pool;
	struct dsasl_client_settings set;
	char *password;
	const struct dsasl_client_mech *mech;
};

struct dsasl_client_mech {
	const char *name;
	size_t struct_size;

	int (*input)(struct dsasl_client *client,
		     const unsigned char *input,
		     unsigned int input_len,
		     const char **error_r);
	int (*output)(struct dsasl_client *client,
		      const unsigned char **output_r,
		      unsigned int *output_len_r,
		      const char **error_r);
	void (*free)(struct dsasl_client *client);
};

extern const struct dsasl_client_mech dsasl_client_mech_login;

void dsasl_client_mech_register(const struct dsasl_client_mech *mech);
void dsasl_client_mech_unregister(const struct dsasl_client_mech *mech);

#endif
