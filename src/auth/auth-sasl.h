#ifndef AUTH_SASL_H
#define AUTH_SASL_H

#include "auth-request.h" // FIXME: remove
#include "sasl-server.h"

/* Used only for string sanitization. */
#define AUTH_SASL_MAX_MECH_NAME_LEN 64

struct auth_sasl_mech_module {
	const char *mech_name;
};

/*
 * Request
 */

void
auth_sasl_request_output(struct auth_request *request,
			 const struct sasl_server_output *output);

/*
 * Mechanisms
 */

void auth_sasl_mech_register_module(
	const struct auth_sasl_mech_module *module);
void auth_sasl_mech_unregister_module(
	const struct auth_sasl_mech_module *module);
const struct auth_sasl_mech_module *
auth_sasl_mech_module_find(const char *name);

#endif
