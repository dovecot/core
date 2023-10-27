#ifndef SASL_SERVER_MECH_SCRAM_H
#define SASL_SERVER_MECH_SCRAM_H

struct sasl_server_mech_request *
mech_scram_auth_new(const struct sasl_server_mech *mech, pool_t pool);
void mech_scram_auth_continue(struct sasl_server_mech_request *auth_request,
			      const unsigned char *input, size_t input_len);

struct sasl_server_mech *mech_scram_mech_new(pool_t pool);

void sasl_server_mech_register_scram(
	struct sasl_server_instance *sinst,
	const struct sasl_server_mech_def *mech_def,
	const struct hash_method *hash_method, const char *password_scheme);

#endif
