#ifndef SASL_SERVER_H
#define SASL_SERVER_H

#include "sasl-common.h"

struct sasl_passdb_result;
struct sasl_server_mech;
struct sasl_server_request;
struct sasl_server_req_ctx;
struct sasl_server_instance;
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

struct sasl_server_settings {
	const char *const *realms;

	/* Event to use for the SASL server instance. */
	struct event *event_parent;

	/* Enable logging verbosity */
	bool verbose:1;
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

enum sasl_server_request_state {
	/* Request is newly created */
	SASL_SERVER_REQUEST_STATE_NEW = 0,
	/* Server needs to act next on this request */
	SASL_SERVER_REQUEST_STATE_SERVER,
	/* Client needs to act next on this request */
	SASL_SERVER_REQUEST_STATE_CLIENT,
	/* Server is waiting for passdb lookup */
	SASL_SERVER_REQUEST_STATE_PASSDB,
	/* Request is finished */
	SASL_SERVER_REQUEST_STATE_FINISHED,
	/* Request is aborted */
	SASL_SERVER_REQUEST_STATE_ABORTED,
};

struct sasl_server_req_ctx {
	const struct sasl_server_mech *mech;
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
				const struct sasl_server_mech *mech,
				const char *protocol,
				struct event *event_parent);
void sasl_server_request_ref(struct sasl_server_req_ctx *rctx);
void sasl_server_request_unref(struct sasl_server_req_ctx *rctx);
void sasl_server_request_destroy(struct sasl_server_req_ctx *rctx);

void sasl_server_request_initial(struct sasl_server_req_ctx *rctx,
				 const unsigned char *data, size_t data_size);
void sasl_server_request_input(struct sasl_server_req_ctx *rctx,
			       const unsigned char *data, size_t data_size);

bool ATTR_PURE
sasl_server_request_has_failed(const struct sasl_server_req_ctx *rctx);

/* Test */

// FIXME: get rid of this
void sasl_server_request_test_set_authid(struct sasl_server_req_ctx *rctx,
					 const char *authid);
void sasl_server_mech_digest_md5_test_set_nonce(
	struct sasl_server_req_ctx *rctx, const char *nonce);

/*
 * Mechanism definitions
 */

void sasl_server_mech_register_anonymous(struct sasl_server_instance *sinst);
void sasl_server_mech_register_cram_md5(struct sasl_server_instance *sinst);
void sasl_server_mech_register_digest_md5(struct sasl_server_instance *sinst);
void sasl_server_mech_register_external(struct sasl_server_instance *sinst);
void sasl_server_mech_register_login(struct sasl_server_instance *sinst);
void sasl_server_mech_register_plain(struct sasl_server_instance *sinst);

void sasl_server_mech_register_scram_sha1(
	struct sasl_server_instance *sinst);
void sasl_server_mech_register_scram_sha1_plus(
	struct sasl_server_instance *sinst);
void sasl_server_mech_register_scram_sha256(
	struct sasl_server_instance *sinst);
void sasl_server_mech_register_scram_sha256_plus(
	struct sasl_server_instance *sinst);

void sasl_server_mech_register_otp(struct sasl_server_instance *sinst);

/* OAUTH2 */

void sasl_server_mech_register_oauthbearer(struct sasl_server_instance *sinst);
void sasl_server_mech_register_xoauth2(struct sasl_server_instance *sinst);

/* Winbind */

struct sasl_server_winbind_settings {
	const char *helper_path;
};

void sasl_server_mech_register_winbind_ntlm(
	struct sasl_server_instance *sinst,
	const struct sasl_server_winbind_settings *set);
void sasl_server_mech_register_winbind_gss_spnego(
	struct sasl_server_instance *sinst,
	const struct sasl_server_winbind_settings *set);

/*
 * Mechanism
 */

struct sasl_server_mech_iter {
	const char *name;

	enum sasl_mech_security_flags flags;
	enum sasl_mech_passdb_need passdb_need;
};

const char * ATTR_PURE
sasl_server_mech_get_name(const struct sasl_server_mech *mech);
enum sasl_mech_security_flags ATTR_PURE
sasl_server_mech_get_security_flags(const struct sasl_server_mech *mech);
enum sasl_mech_passdb_need ATTR_PURE
sasl_server_mech_get_passdb_need(const struct sasl_server_mech *mech);

const struct sasl_server_mech *
sasl_server_mech_find(struct sasl_server_instance *sinst, const char *name);

struct sasl_server_mech_iter *
sasl_server_mech_iter_new(struct sasl_server *server);
struct sasl_server_mech_iter *
sasl_server_instance_mech_iter_new(struct sasl_server_instance *sinst);
bool sasl_server_mech_iter_next(struct sasl_server_mech_iter *iter);
bool sasl_server_mech_iter_ended(struct sasl_server_mech_iter *iter);
void sasl_server_mech_iter_free(struct sasl_server_mech_iter **_iter);

/*
 * Instance
 */

struct sasl_server_instance *
sasl_server_instance_create(struct sasl_server *server,
			    const struct sasl_server_settings *set);
void sasl_server_instance_ref(struct sasl_server_instance *sinst);
void sasl_server_instance_unref(struct sasl_server_instance **_sinst);

/*
 * Server
 */

struct sasl_server *
sasl_server_init(struct event *event_parent,
		 const struct sasl_server_request_funcs *funcs);
void sasl_server_deinit(struct sasl_server **_server);

#endif
