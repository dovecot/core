#ifndef SASL_SERVER_PROTECTED_H
#define SASL_SERVER_PROTECTED_H

#include "passdb.h" // FIXME: remove
#include "auth-request-handler.h"

#include "sasl-server.h"

struct auth_request;

struct mech_module {
	const char *mech_name;

	enum mech_security_flags flags;
	enum mech_passdb_need passdb_need;

	struct auth_request *(*auth_new)(void);
	void (*auth_initial)(struct auth_request *request,
			     const unsigned char *data, size_t data_size);
	void (*auth_continue)(struct auth_request *request,
			      const unsigned char *data, size_t data_size);
	void (*auth_free)(struct auth_request *request);
};

struct mech_module_list {
	struct mech_module_list *next;

	struct mech_module module;
};

struct mechanisms_register {
	pool_t pool;
	const struct auth_settings *set;

	struct mech_module_list *modules;
	buffer_t *handshake;
	buffer_t *handshake_cbind;
};

/*
 * Mechanism
 */

extern const struct mech_module mech_dovecot_token;

void mech_register_module(const struct mech_module *module);
void mech_unregister_module(const struct mech_module *module);
const struct mech_module *mech_module_find(const char *name);

void sasl_server_mech_generic_auth_initial(struct auth_request *request,
					   const unsigned char *data,
					   size_t data_size);
void sasl_server_mech_generic_auth_free(struct auth_request *request);

struct mechanisms_register *
mech_register_init(const struct auth_settings *set);
void mech_register_deinit(struct mechanisms_register **reg);
const struct mech_module *
mech_register_find(const struct mechanisms_register *reg, const char *name);

void mech_init(const struct auth_settings *set);
void mech_deinit(const struct auth_settings *set);

void mech_oauth2_initialize(void);

/*
 * Request
 */

void sasl_server_request_output(struct auth_request *request,
				const void *data, size_t data_size);
void sasl_server_request_success(struct auth_request *request,
				 const void *data, size_t data_size);
void sasl_server_request_failure_with_reply(struct auth_request *request,
					    const void *data, size_t data_size);
void sasl_server_request_failure(struct auth_request *request);
void sasl_server_request_internal_failure(struct auth_request *request);

void sasl_server_request_verify_plain(
	struct auth_request *request, const char *password,
	sasl_server_verify_plain_callback_t *callback);

#endif
