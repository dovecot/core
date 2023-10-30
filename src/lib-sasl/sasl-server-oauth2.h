#ifndef SASL_SERVER_OAUTH2_H
#define SASL_SERVER_OAUTH2_H

#include "sasl-server.h"

struct sasl_server_oauth2_failure {
	const char *status;
	const char *scope;
};

struct sasl_server_oauth2_request {
	pool_t pool;
	struct sasl_server_req_ctx *rctx;
};

struct sasl_server_oauth2_settings {
	const char *openid_configuration_url;
};

struct sasl_server_oauth2_funcs {
	int (*auth_new)(struct sasl_server_req_ctx *rctx, pool_t pool,
			const char *token,
			struct sasl_server_oauth2_request **req_r);
	void (*auth_free)(struct sasl_server_oauth2_request *req);
};

static inline void
sasl_server_oauth2_request_init(struct sasl_server_oauth2_request *request_r,
				pool_t pool, struct sasl_server_req_ctx *srctx)
{
	i_zero(request_r);
	request_r->pool = pool;
	request_r->rctx = srctx;
}

void sasl_server_oauth2_request_succeed(struct sasl_server_req_ctx *rctx);
void sasl_server_oauth2_request_fail(
	struct sasl_server_req_ctx *rctx,
	const struct sasl_server_oauth2_failure *failure);

struct sasl_server_oauth2_request *
sasl_server_oauth2_request_get(struct sasl_server_req_ctx *rctx);

void sasl_server_mech_register_oauthbearer(
	struct sasl_server_instance *sinst,
	const struct sasl_server_oauth2_funcs *funcs,
	const struct sasl_server_oauth2_settings *set);
void sasl_server_mech_register_xoauth2(
	struct sasl_server_instance *sinst,
	const struct sasl_server_oauth2_funcs *funcs,
	const struct sasl_server_oauth2_settings *set);

#endif
