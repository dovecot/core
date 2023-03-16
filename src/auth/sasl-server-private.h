#ifndef SASL_SERVER_PRIVATE_H
#define SASL_SERVER_PRIVATE_H

#include "sasl-server-protected.h"

enum sasl_server_passdb_type {
	SASL_SERVER_PASSDB_TYPE_VERIFY_PLAIN,
	SASL_SERVER_PASSDB_TYPE_LOOKUP_CREDENTIALS,
	SASL_SERVER_PASSDB_TYPE_SET_CREDENTIALS,
};

struct sasl_server_request {
	pool_t pool;
	struct sasl_server_req_ctx *rctx;
	struct sasl_server_mech_request *mech;

	enum sasl_server_passdb_type passdb_type;
	sasl_server_mech_passdb_callback_t *passdb_callback;
};

#endif
