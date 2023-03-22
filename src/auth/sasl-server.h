#ifndef SASL_SERVER_H
#define SASL_SERVER_H

#include "sasl-common.h"

struct sasl_passdb_result;
struct sasl_server_mech_def;
struct sasl_server_request;
struct sasl_server_req_ctx;
struct sasl_server;

enum sasl_passdb_result_status {
	SASL_PASSDB_RESULT_INTERNAL_FAILURE = -1,
	SASL_PASSDB_RESULT_SCHEME_NOT_AVAILABLE = -2,

	SASL_PASSDB_RESULT_USER_UNKNOWN = -3,
	SASL_PASSDB_RESULT_USER_DISABLED = -4,
	SASL_PASSDB_RESULT_PASS_EXPIRED = -5,

	SASL_PASSDB_RESULT_PASSWORD_MISMATCH = 0,
	SASL_PASSDB_RESULT_OK = 1,
};

enum sasl_mech_passdb_need {
	/* Mechanism doesn't need a passdb at all */
	SASL_MECH_PASSDB_NEED_NOTHING = 0,
	/* Mechanism just needs to verify a given plaintext password */
	SASL_MECH_PASSDB_NEED_VERIFY_PLAIN,
	/* Mechanism needs to verify a given challenge+response combination,
	   i.e. there is only a single response from client.
	   (Currently implemented the same as _LOOKUP_CREDENTIALS) */
	SASL_MECH_PASSDB_NEED_VERIFY_RESPONSE,
	/* Mechanism needs to look up credentials with appropriate scheme */
	SASL_MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,
	/* Mechanism needs to look up credentials and also modify them */
	SASL_MECH_PASSDB_NEED_SET_CREDENTIALS,
};

enum sasl_server_output_status {
	/* Internal failure */
	SASL_SERVER_OUTPUT_INTERNAL_FAILURE = -2,
	/* Authentication failed */
	SASL_SERVER_OUTPUT_FAILURE = -1,
	/* Client is challlenged to continue authentication */
	SASL_SERVER_OUTPUT_CONTINUE = 0,
	/* Authentication succeeded */
	SASL_SERVER_OUTPUT_SUCCESS = 1,
};

typedef void
sasl_server_passdb_callback_t(struct sasl_server_req_ctx *rctx,
			      const struct sasl_passdb_result *result);

struct sasl_server_output {
	enum sasl_server_output_status status;

	const void *data;
	size_t data_size;
};

struct sasl_passdb_result {
	enum sasl_passdb_result_status status;

	struct {
		const unsigned char *data;
		size_t size;
	} credentials;
};

/*
 * Request
 */

enum sasl_server_authid_type {
	/* Normal authentication ID (username) */
	SASL_SERVER_AUTHID_TYPE_USERNAME = 0,
	/* Anonymous credentials; there is no verified authentication ID. */
	SASL_SERVER_AUTHID_TYPE_ANONYMOUS,
	/* The authentication ID is set and verified by an external source. */
	SASL_SERVER_AUTHID_TYPE_EXTERNAL,
};

struct sasl_server_req_ctx {
	const struct sasl_server_mech_def *mech;
	const char *mech_name;

	struct sasl_server_request *request;
};

struct sasl_server_request_funcs {
	bool (*request_set_authid)(struct sasl_server_req_ctx *rctx,
				   enum sasl_server_authid_type authid_type,
				   const char *authid);
	bool (*request_set_authzid)(struct sasl_server_req_ctx *rctx,
				    const char *authzid);
	void (*request_set_realm)(struct sasl_server_req_ctx *rctx,
				  const char *realm);

	bool (*request_get_extra_field)(struct sasl_server_req_ctx *rctx,
					const char *name, const char **field_r);

	void (*request_start_channel_binding)(struct sasl_server_req_ctx *rctx,
					      const char *type);
	int (*request_accept_channel_binding)(struct sasl_server_req_ctx *rctx,
					      buffer_t **data_r);

	void (*request_output)(struct sasl_server_req_ctx *rctx,
			       const struct sasl_server_output *output);

	void (*request_verify_plain)(
		struct sasl_server_req_ctx *rctx, const char *password,
		sasl_server_passdb_callback_t *callback);
	void (*request_lookup_credentials)(
		struct sasl_server_req_ctx *rctx, const char *scheme,
		sasl_server_passdb_callback_t *callback);
	void (*request_set_credentials)(
		struct sasl_server_req_ctx *rctx,
		const char *scheme, const char *data,
		sasl_server_passdb_callback_t *callback);
};

void sasl_server_request_create(struct sasl_server_req_ctx *rctx,
				struct sasl_server *server,
				const struct sasl_server_mech_def *mech,
				const char *protocol,
				struct event *event_parent);
void sasl_server_request_destroy(struct sasl_server_req_ctx *rctx);

void sasl_server_request_initial(struct sasl_server_req_ctx *rctx,
				 const unsigned char *data, size_t data_size);
void sasl_server_request_input(struct sasl_server_req_ctx *rctx,
			       const unsigned char *data, size_t data_size);

/*
 * Server
 */

struct sasl_server *
sasl_server_init(struct event *event_parent,
		 const struct sasl_server_request_funcs *funcs);
void sasl_server_deinit(struct sasl_server **_server);

#endif
