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

bool
auth_sasl_request_set_authid(struct auth_request *request,
			     enum sasl_server_authid_type authid_type,
			     const char *authid);

bool
auth_sasl_request_set_authzid(struct auth_request *request,
			      const char *authzid);


void
auth_sasl_request_output(struct auth_request *request,
			 const struct sasl_server_output *output);

void
auth_sasl_request_verify_plain(struct auth_request *request,
			       const char *password,
			       verify_plain_callback_t *verify_plain_callback);

void
auth_sasl_request_lookup_credentials(struct auth_request *request,
				     const char *scheme,
				     lookup_credentials_callback_t *lookup_credentials_callback);

void
auth_sasl_request_set_credentials(struct auth_request *request,
				  const char *scheme, const char *data,
				  set_credentials_callback_t  *set_credentials_callback);

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
