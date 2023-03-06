#ifndef SASL_SERVER_MECH_SCRAM_H
#define SASL_SERVER_MECH_SCRAM_H

struct sasl_server_mech_request *
mech_scram_auth_new(pool_t pool, const struct hash_method *hash_method,
		    const char *password_scheme);
void mech_scram_auth_continue(struct sasl_server_mech_request *auth_request,
			      const unsigned char *input, size_t input_len);

#endif
