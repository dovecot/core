#ifndef SASL_SERVER_MECH_PLAIN_COMMON_H
#define SASL_SERVER_MECH_PLAIN_COMMON_H

void sasl_server_mech_plain_verify_callback(enum passdb_result result,
					    struct auth_request *request);

#endif
