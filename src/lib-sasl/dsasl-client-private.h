#ifndef DSASL_CLIENT_PRIVATE_H
#define DSASL_CLIENT_PRIVATE_H

#include "dsasl-client-protected.h"

struct dsasl_client_session {
	pool_t pool;
	int refcount;
	struct event *event;
	struct dsasl_client_mech_session *mech;

	dsasl_client_channel_binding_callback_t *cbinding_callback;
	void *cbinding_context;
};

#endif
