#ifndef SASL_SERVER_PROTECTED_H
#define SASL_SERVER_PROTECTED_H

#include "auth-request.h" // FIXME: remove

#include "sasl-server.h"

struct auth_request;
struct sasl_server_mech_request;

typedef void
sasl_server_mech_passdb_callback_t(struct sasl_server_mech_request *req,
				   const struct sasl_passdb_result *result);

struct sasl_server_mech_def {
	const char *mech_name;

	enum sasl_mech_security_flags flags;
	enum sasl_mech_passdb_need passdb_need;

	struct sasl_server_mech_request *(*auth_new)(pool_t pool);
	void (*auth_initial)(struct sasl_server_mech_request *req,
			     const unsigned char *data, size_t data_size);
	void (*auth_continue)(struct sasl_server_mech_request *req,
			      const unsigned char *data, size_t data_size);
	void (*auth_free)(struct sasl_server_mech_request *req);
};

struct mech_module_list {
	struct mech_module_list *next;

	const struct sasl_server_mech_def *module;
};

struct mechanisms_register {
	pool_t pool;
	const struct auth_settings *set;

	struct mech_module_list *modules;
	buffer_t *handshake;
	buffer_t *handshake_cbind;
};

struct sasl_server_mech_request {
	pool_t pool;
	const struct sasl_server_mech_def *mech;
	struct sasl_server_request *req;
	struct event *mech_event;

	const char *protocol;
	const char *authid;
	const char *realm;

	const struct sasl_server_settings *set;

	// FIXME: To be removed
	struct auth_request *request;
};

/*
 * Mechanism
 */

extern const struct sasl_server_mech_def mech_dovecot_token;

void mech_register_module(const struct sasl_server_mech_def *module);
void mech_unregister_module(const struct sasl_server_mech_def *module);
const struct sasl_server_mech_def *mech_module_find(const char *name);

void sasl_server_mech_generic_auth_initial(
	struct sasl_server_mech_request *mreq,
	const unsigned char *data, size_t data_size);

struct mechanisms_register *
mech_register_init(const struct auth_settings *set);
void mech_register_deinit(struct mechanisms_register **reg);
const struct sasl_server_mech_def *
mech_register_find(const struct mechanisms_register *reg, const char *name);

void mech_init(const struct auth_settings *set);
void mech_deinit(const struct auth_settings *set);

/*
 * Request
 */

bool sasl_server_request_set_authid(struct sasl_server_mech_request *mreq,
				    enum sasl_server_authid_type authid_type,
				    const char *authid);
bool sasl_server_request_set_authzid(struct sasl_server_mech_request *mreq,
				     const char *authzid);
void sasl_server_request_set_realm(struct sasl_server_mech_request *mreq,
				   const char *realm);

bool sasl_server_request_get_extra_field(struct sasl_server_mech_request *mreq,
					 const char *name,
					 const char **field_r);

void sasl_server_request_start_channel_binding(
	struct sasl_server_mech_request *mreq, const char *type);
int sasl_server_request_accept_channel_binding(
	struct sasl_server_mech_request *mreq, buffer_t **data_r);

void sasl_server_request_output(struct sasl_server_mech_request *mreq,
				const void *data, size_t data_size);
void sasl_server_request_success(struct sasl_server_mech_request *mreq,
				 const void *data, size_t data_size);
void sasl_server_request_failure_with_reply(
	struct sasl_server_mech_request *mreq,
	const void *data, size_t data_size);
void sasl_server_request_failure(struct sasl_server_mech_request *mreq);
void sasl_server_request_internal_failure(
	struct sasl_server_mech_request *mreq);

void sasl_server_request_verify_plain(
	struct sasl_server_mech_request *mreq, const char *password,
	sasl_server_mech_passdb_callback_t *callback);
void sasl_server_request_lookup_credentials(
	struct sasl_server_mech_request *mreq, const char *scheme,
	sasl_server_mech_passdb_callback_t *callback);
void sasl_server_request_set_credentials(
	struct sasl_server_mech_request *mreq,
	const char *scheme, const char *data,
	sasl_server_mech_passdb_callback_t *callback);

/* Obtains the mechanism request struct (protected) from the request context
   struct (public). This function meant for providing the means to have
   mechanisms that add their own backend API. If you use this function for
   something else, you are subverting the design of the SASL server API, which
   is to be avoided.
*/
struct sasl_server_mech_request *
sasl_server_request_get_mech_request(struct sasl_server_req_ctx *rctx);

#endif
