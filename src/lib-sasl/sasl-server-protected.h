#ifndef SASL_SERVER_PROTECTED_H
#define SASL_SERVER_PROTECTED_H

#include "sasl-server.h"

struct sasl_server_mech_funcs;
struct sasl_server_mech_def;
struct sasl_server_mech_data;
struct sasl_server_mech_request;

typedef void
sasl_server_mech_passdb_callback_t(struct sasl_server_mech_request *req,
				   const struct sasl_passdb_result *result);

struct sasl_server_mech_funcs {
	struct sasl_server_mech_request *
	(*auth_new)(const struct sasl_server_mech *mech, pool_t pool);
	void (*auth_initial)(struct sasl_server_mech_request *req,
			     const unsigned char *data, size_t data_size);
	void (*auth_continue)(struct sasl_server_mech_request *req,
			      const unsigned char *data, size_t data_size);
	void (*auth_free)(struct sasl_server_mech_request *req);

	/* Global data shared between server instances */
	struct sasl_server_mech_data *(*data_new)(pool_t pool);
	void (*data_free)(struct sasl_server_mech_data *mdata);

	struct sasl_server_mech *(*mech_new)(pool_t pool);
	void (*mech_free)(struct sasl_server_mech *mech);
};

struct sasl_server_mech_def {
	const char *name;

	enum sasl_mech_security_flags flags;
	enum sasl_mech_passdb_need passdb_need;

	const struct sasl_server_mech_funcs *funcs;
};

struct sasl_server_mech_settings {
	enum sasl_mech_passdb_need passdb_need;
};

struct sasl_server_mech_data {
	struct sasl_server *server;
	pool_t pool;

	const struct sasl_server_mech_def *def;
};

struct sasl_server_mech {
	struct sasl_server_instance *sinst;
	struct sasl_server_mech_reg *reg;
	pool_t pool;
	struct event *event;
	struct sasl_server_mech_data *data;

	const struct sasl_server_mech_def *def;
};

struct sasl_server_mech_request {
	pool_t pool;
	const struct sasl_server_mech *mech;
	struct sasl_server_request *req;
	struct event *event;

	const char *protocol;
	const char *authid;
	const char *realm;

	const struct sasl_server_settings *set;
};

/*
 * Mechanism
 */

struct sasl_server_mech * ATTR_NOWARN_UNUSED_RESULT
sasl_server_mech_register(struct sasl_server_instance *sinst,
			  const struct sasl_server_mech_def *def,
			  const struct sasl_server_mech_settings *set);
struct sasl_server_mech * ATTR_NOWARN_UNUSED_RESULT
sasl_server_mech_register_hidden(struct sasl_server_instance *sinst,
				 const struct sasl_server_mech_def *def,
				 const struct sasl_server_mech_settings *set);
void sasl_server_mech_unregister(struct sasl_server_instance *sinst,
				 const struct sasl_server_mech_def *def);

void sasl_server_mech_generic_auth_initial(
	struct sasl_server_mech_request *mreq,
	const unsigned char *data, size_t data_size);

void sasl_server_mech_plain_verify_callback(
	struct sasl_server_mech_request *request,
	const struct sasl_passdb_result *result);

/*
 * Request
 */

void sasl_server_mech_request_ref(struct sasl_server_mech_request *mreq);
void sasl_server_mech_request_unref(struct sasl_server_mech_request **_mreq);

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
void sasl_server_request_password_mismatch(
	struct sasl_server_mech_request *mreq);
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
/* Obtains the request context struct (public) from the mechanism request
   struct (protected). This can be used to create SASL mechanisms that have
   broader access to the application. This is normally not needed and should
   only be used for custom mechanisms for internal use. */
struct sasl_server_req_ctx *
sasl_server_request_get_req_ctx(struct sasl_server_mech_request *mreq);

#endif
