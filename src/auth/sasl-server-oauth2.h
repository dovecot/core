#ifndef SASL_SERVER_OAUTH2_H
#define SASL_SERVER_OAUTH2_H

#include "sasl-server.h"

struct sasl_server_oauth2_failure {
	const char *status;
	const char *scope;
	const char *openid_configuration;
};

#endif
