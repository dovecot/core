#ifndef SASL_SERVER_MECH_PLAIN_COMMON_H
#define SASL_SERVER_MECH_PLAIN_COMMON_H

void plain_verify_callback(enum passdb_result result,
			   struct auth_request *request);

#endif
