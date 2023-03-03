#ifndef MECH_SCRAM_H
#define MECH_SCRAM_H

struct auth_request *
mech_scram_auth_new(const struct hash_method *hash_method,
		    const char *password_scheme);
void mech_scram_auth_continue(struct auth_request *auth_request,
			      const unsigned char *data, size_t data_size);

#endif
