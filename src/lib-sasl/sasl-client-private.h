#ifndef SASL_CLIENT_PRIVATE_H
#define SASL_CLIENT_PRIVATE_H

#include "sasl-client.h"

struct sasl_client {
	pool_t pool;
	struct sasl_client_settings set;
	char *password;
	const struct sasl_client_mech *mech;
};

struct sasl_client_mech {
	const char *name;
	size_t struct_size;

	int (*input)(struct sasl_client *client,
		     const unsigned char *input,
		     unsigned int input_len,
		     const char **error_r);
	int (*output)(struct sasl_client *client,
		      const unsigned char **output_r,
		      unsigned int *output_len_r,
		      const char **error_r);
	void (*free)(struct sasl_client *client);
};

extern const struct sasl_client_mech sasl_client_mech_login;

void sasl_client_mech_register(const struct sasl_client_mech *mech);
void sasl_client_mech_unregister(const struct sasl_client_mech *mech);

#endif
