#ifndef SASL_SERVER_OAUTH2_H
#define SASL_SERVER_OAUTH2_H

#include "sasl-server.h"

struct sasl_server_oauth2_failure {
	const char *status;
	const char *scope;
	const char *openid_configuration;
};

void sasl_server_oauth2_request_succeed(struct auth_request *request);
void sasl_server_oauth2_request_fail(
	struct auth_request *request,
	const struct sasl_server_oauth2_failure *failure);

#endif
