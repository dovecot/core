#ifndef SASL_SERVER_MECH_SCRAM_H
#define SASL_SERVER_MECH_SCRAM_H

extern const struct sasl_server_mech_funcs sasl_server_mech_scram_funcs;

void sasl_server_mech_register_scram(
	struct sasl_server_instance *sinst,
	const struct sasl_server_mech_def *mech_def,
	const struct hash_method *hash_method, const char *password_scheme);

#endif
