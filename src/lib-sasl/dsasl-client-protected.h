#ifndef DSASL_CLIENT_PROTECTED_H
#define DSASL_CLIENT_PROTECTED_H

#include "sasl-common.h"
#include "dsasl-client.h"

struct dsasl_client_mech_session {
	pool_t pool;
	struct event *event;
	const struct dsasl_client_mech *mech;
	struct dsasl_client_settings set;
	struct dsasl_client_session *session;

	char *password;

	enum ssl_iostream_protocol_version channel_version;
};

#endif
