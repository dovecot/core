#ifndef AUTH_SASL_H
#define AUTH_SASL_H

#include "sasl-server.h"
#include "auth-sasl-common.h"

/* Used only for string sanitization. */
#define AUTH_SASL_MAX_MECH_NAME_LEN 64

struct auth_request;
struct auth_settings;

struct auth_sasl_mech_module {
	const char *mech_name;

	bool (*mech_register)(struct sasl_server_instance *sasl_inst,
			      const struct auth_settings *set);
	void (*mech_unregister)(struct sasl_server_instance *sasl_inst);
};

/*
 * Request
 */

void auth_sasl_request_init(struct auth_request *request,
			    const struct sasl_server_mech *mech);
void auth_sasl_request_deinit(struct auth_request *request);

void auth_sasl_request_initial(struct auth_request *request);
void auth_sasl_request_continue(struct auth_request *request,
				const unsigned char *data, size_t data_size);

/*
 * Mechanisms
 */

void auth_sasl_mech_register_apop(struct sasl_server_instance *sinst);
const struct sasl_server_mech *
auth_sasl_mech_register_dovecot_token(struct sasl_server_instance *sinst);

void auth_sasl_mech_register_module(
	const struct auth_sasl_mech_module *module);
void auth_sasl_mech_unregister_module(
	const struct auth_sasl_mech_module *module);
const struct auth_sasl_mech_module *
auth_sasl_mech_module_find(const char *name);

const char *auth_sasl_mechs_get_handshake(void);
const char *auth_sasl_mechs_get_handshake_cbind(void);

/*
 * Instance
 */

void auth_sasl_instance_init(struct auth *auth,
			     const struct auth_settings *set);
void auth_sasl_instance_verify(const struct auth *auth);
void auth_sasl_instance_deinit(struct auth *auth);

/*
 * Global
 */

void auth_sasl_preinit(const struct auth_settings *set);
void auth_sasl_init(void);
void auth_sasl_deinit(void);

#endif
