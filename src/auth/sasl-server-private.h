#ifndef SASL_SERVER_PRIVATE_H
#define SASL_SERVER_PRIVATE_H

#include "sasl-server-protected.h"

struct sasl_server_request {
	struct sasl_server_mech_request *mech;
};

#endif
