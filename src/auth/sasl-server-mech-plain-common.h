#ifndef SASL_SERVER_MECH_PLAIN_COMMON_H
#define SASL_SERVER_MECH_PLAIN_COMMON_H

void sasl_server_mech_plain_verify_callback(
	struct sasl_server_mech_request *request,
	const struct sasl_passdb_result *result);

#endif
