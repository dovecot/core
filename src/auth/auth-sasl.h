#ifndef AUTH_SASL_H
#define AUTH_SASL_H

#include "sasl-server.h"

/* Used only for string sanitization. */
#define AUTH_SASL_MAX_MECH_NAME_LEN 64

struct auth_request;
struct auth_settings;

struct auth_sasl_mech_module {
	const char *mech_name;
};

/*
 * Request
 */

void auth_sasl_request_init(struct auth_request *request,
			    const struct sasl_server_mech_def *mech);
void auth_sasl_request_deinit(struct auth_request *request);

void auth_sasl_request_initial(struct auth_request *request);
void auth_sasl_request_continue(struct auth_request *request,
				const unsigned char *data, size_t data_size);

/*
 * Mechanisms
 */

void auth_sasl_mech_register_module(
	const struct auth_sasl_mech_module *module);
void auth_sasl_mech_unregister_module(
	const struct auth_sasl_mech_module *module);
const struct auth_sasl_mech_module *
auth_sasl_mech_module_find(const char *name);

/*
 * Instance
 */

void auth_sasl_instance_init(struct auth *auth);
void auth_sasl_instance_deinit(struct auth *auth);

/*
 * Global
 */

void auth_sasl_preinit(void);
void auth_sasl_init(void);
void auth_sasl_deinit(void);

#endif
