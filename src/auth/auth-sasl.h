#ifndef AUTH_SASL_H
#define AUTH_SASL_H

#include "sasl-server.h"

/* Used only for string sanitization. */
#define AUTH_SASL_MAX_MECH_NAME_LEN 64

struct auth_request;

struct auth_sasl_mech_module {
	const char *mech_name;
};

/*
 * Request
 */

bool
auth_sasl_request_set_authid(struct sasl_server_req_ctx *rctx,
			     enum sasl_server_authid_type authid_type,
			     const char *authid);

bool
auth_sasl_request_set_authzid(struct sasl_server_req_ctx *rctx,
			      const char *authzid);

void
auth_sasl_request_set_realm(struct sasl_server_req_ctx *rctx,
			    const char *realm);

bool
auth_sasl_request_get_extra_field(struct sasl_server_req_ctx *rctx,
				  const char *name, const char **field_r);

void
auth_sasl_request_start_channel_binding(struct sasl_server_req_ctx *rctx,
					const char *type);
int
auth_sasl_request_accept_channel_binding(struct sasl_server_req_ctx *rctx,
					 buffer_t **data_r);

void
auth_sasl_request_output(struct sasl_server_req_ctx *rctx,
			 const struct sasl_server_output *output);

void
auth_sasl_request_verify_plain(struct sasl_server_req_ctx *rctx,
			       const char *password,
			       sasl_server_passdb_callback_t *callback);

void
auth_sasl_request_lookup_credentials(struct sasl_server_req_ctx *rctx,
				     const char *scheme,
				     sasl_server_passdb_callback_t *callback);

void
auth_sasl_request_set_credentials(struct sasl_server_req_ctx *rctx,
				  const char *scheme, const char *data,
				  sasl_server_passdb_callback_t *callback);

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

#endif
