/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-request.h"

#include "sasl-server-private.h"

/*
 * Public API
 */

void sasl_server_request_create(struct sasl_server_req_ctx *rctx,
				struct sasl_server_instance *sinst,
				const struct sasl_server_mech_def *mech,
				const char *protocol,
				struct event *event_parent)
{
	struct sasl_server *server = sinst->server;
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);
	struct sasl_server_request *req;
	pool_t pool;

	i_zero(rctx);

	pool = request->pool;
	req = p_new(pool, struct sasl_server_request, 1);
	req->pool = pool;
	req->sinst = sinst;
	req->rctx = rctx;

	sinst->requests++;
	server->requests++;

	struct sasl_server_mech_request *mreq;

	if (mech->auth_new != NULL)
		mreq = mech->auth_new(pool);
	else
		mreq = p_new(pool, struct sasl_server_mech_request, 1);
	mreq->pool = pool;
	mreq->req = req;
	mreq->request = request;
	mreq->set = &sinst->set;
	mreq->mech = mech;
	mreq->mech_event = event_parent;
	mreq->protocol = p_strdup(mreq->pool, protocol);

	req->mech = mreq;
	rctx->mech = mech;
	rctx->mech_name = mech->mech_name;
	rctx->request = req;
}

void sasl_server_request_destroy(struct sasl_server_req_ctx *rctx)
{
	struct sasl_server_request *req = rctx->request;

	i_zero(rctx);
	if (req == NULL)
		return;

	struct sasl_server_instance *sinst = req->sinst;
	struct sasl_server *server = sinst->server;
	struct sasl_server_mech_request *mreq = req->mech;

	i_assert(sinst->requests > 0);
	sinst->requests--;
	i_assert(server->requests > 0);
	server->requests--;

	if (mreq->mech->auth_free != NULL)
		mreq->mech->auth_free(mreq);
}

static bool
sasl_server_request_fail_on_nuls(struct sasl_server_request *req,
				 const unsigned char *data, size_t data_size)
{
	const struct sasl_server_mech_def *mech = req->mech->mech;

	if ((mech->flags & SASL_MECH_SEC_ALLOW_NULS) != 0)
		return FALSE;
	if (memchr(data, '\0', data_size) != NULL) {
		e_debug(req->mech->mech_event, "Unexpected NUL in auth data");
		sasl_server_request_failure(req->mech);
		return TRUE;
	}
	return FALSE;
}

void sasl_server_request_initial(struct sasl_server_req_ctx *rctx,
				 const unsigned char *data, size_t data_size)
{
	struct sasl_server_request *req = rctx->request;
	struct sasl_server_mech_request *mreq = req->mech;
	const struct sasl_server_mech_def *mech = mreq->mech;

	if (sasl_server_request_fail_on_nuls(req, data, data_size))
		return;

	i_assert(mech->auth_initial != NULL);
	mech->auth_initial(mreq, data, data_size);
}

void sasl_server_request_input(struct sasl_server_req_ctx *rctx,
			       const unsigned char *data, size_t data_size)
{
	struct sasl_server_request *req = rctx->request;
	struct sasl_server_mech_request *mreq = req->mech;
	const struct sasl_server_mech_def *mech = mreq->mech;

	if (sasl_server_request_fail_on_nuls(req, data, data_size))
		return;

	i_assert(mech->auth_continue != NULL);
	mech->auth_continue(mreq, data, data_size);
}

void sasl_server_request_test_set_authid(struct sasl_server_req_ctx *rctx,
					 const char *authid)
{
	struct sasl_server_request *req = rctx->request;

	req->mech->authid = p_strdup(req->mech->pool, authid);
}

/*
 * Mechanism API
 */

bool sasl_server_request_set_authid(struct sasl_server_mech_request *mreq,
				    enum sasl_server_authid_type authid_type,
				    const char *authid)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	mreq->authid = p_strdup(req->pool, authid);

	i_assert(funcs->request_set_authid != NULL);
	return funcs->request_set_authid(req->rctx, authid_type, authid);
}

bool sasl_server_request_set_authzid(struct sasl_server_mech_request *mreq,
				     const char *authzid)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	i_assert(funcs->request_set_authzid != NULL);
	return funcs->request_set_authzid(req->rctx, authzid);
}

void sasl_server_request_set_realm(struct sasl_server_mech_request *mreq,
				   const char *realm)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	i_assert(mreq->realm == NULL);
	mreq->realm = p_strdup(req->pool, realm);

	i_assert(funcs->request_set_realm != NULL);
	funcs->request_set_realm(req->rctx, realm);
}

bool sasl_server_request_get_extra_field(struct sasl_server_mech_request *mreq,
					 const char *name,
					 const char **field_r)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	if (funcs->request_get_extra_field == NULL) {
		*field_r = NULL;
		return FALSE;
	}
	return funcs->request_get_extra_field(req->rctx, name, field_r);
}

void sasl_server_request_start_channel_binding(
	struct sasl_server_mech_request *mreq, const char *type)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	i_assert(funcs->request_start_channel_binding != NULL);
	funcs->request_start_channel_binding(req->rctx, type);
}

int sasl_server_request_accept_channel_binding(
	struct sasl_server_mech_request *mreq, buffer_t **data_r)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	i_assert(funcs->request_accept_channel_binding != NULL);
	return funcs->request_accept_channel_binding(req->rctx, data_r);
}

void sasl_server_request_output(struct sasl_server_mech_request *mreq,
				const void *data, size_t data_size)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	const struct sasl_server_output output = {
		.status = SASL_SERVER_OUTPUT_CONTINUE,
		.data = data,
		.data_size = data_size,
	};
	i_assert(funcs->request_output != NULL);
	funcs->request_output(req->rctx, &output);
}

void sasl_server_request_success(struct sasl_server_mech_request *mreq,
				 const void *data, size_t data_size)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	const struct sasl_server_output output = {
		.status = SASL_SERVER_OUTPUT_SUCCESS,
		.data = data,
		.data_size = data_size,
	};
	i_assert(funcs->request_output != NULL);
	funcs->request_output(req->rctx, &output);
}

static void
sasl_server_request_failure_common(struct sasl_server_mech_request *mreq,
				   enum sasl_server_output_status status,
				   const void *data, size_t data_size)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	const struct sasl_server_output output = {
		.status = status,
		.data = data,
		.data_size = data_size,
	};
	i_assert(funcs->request_output != NULL);
	funcs->request_output(req->rctx, &output);
}

void sasl_server_request_failure_with_reply(
	struct sasl_server_mech_request *mreq,
	const void *data, size_t data_size)
{
	sasl_server_request_failure_common(mreq, SASL_SERVER_OUTPUT_FAILURE,
					   data, data_size);
}

void sasl_server_request_failure(struct sasl_server_mech_request *mreq)
{
	sasl_server_request_failure_common(mreq, SASL_SERVER_OUTPUT_FAILURE,
					   "", 0);
}

void sasl_server_request_internal_failure(
	struct sasl_server_mech_request *mreq)
{
	sasl_server_request_failure_common(
		mreq, SASL_SERVER_OUTPUT_INTERNAL_FAILURE, "", 0);
}

static void
verify_plain_callback(struct sasl_server_req_ctx *rctx,
		      const struct sasl_passdb_result *result)
{
	struct sasl_server_request *req = rctx->request;

	i_assert(req->passdb_type == SASL_SERVER_PASSDB_TYPE_VERIFY_PLAIN);
	req->passdb_callback(req->mech, result);
}

void sasl_server_request_verify_plain(
	struct sasl_server_mech_request *mreq, const char *password,
	sasl_server_mech_passdb_callback_t *callback)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	req->passdb_type = SASL_SERVER_PASSDB_TYPE_VERIFY_PLAIN;
	req->passdb_callback = callback;

	i_assert(funcs->request_verify_plain != NULL);
	funcs->request_verify_plain(req->rctx, password,
				    verify_plain_callback);
}

static void
lookup_credentials_callback(struct sasl_server_req_ctx *rctx,
			    const struct sasl_passdb_result *result)
{
	struct sasl_server_request *req = rctx->request;

	i_assert(req->passdb_type ==
		 SASL_SERVER_PASSDB_TYPE_LOOKUP_CREDENTIALS);
	req->passdb_callback(req->mech, result);
}

void sasl_server_request_lookup_credentials(
	struct sasl_server_mech_request *mreq, const char *scheme,
	sasl_server_mech_passdb_callback_t *callback)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	req->passdb_type = SASL_SERVER_PASSDB_TYPE_LOOKUP_CREDENTIALS;
	req->passdb_callback = callback;

	i_assert(funcs->request_lookup_credentials != NULL);
	funcs->request_lookup_credentials(req->rctx, scheme,
					  lookup_credentials_callback);
}

static void
set_credentials_callback(struct sasl_server_req_ctx *rctx,
			 const struct sasl_passdb_result *result)
{
	struct sasl_server_request *req = rctx->request;

	i_assert(req->passdb_type == SASL_SERVER_PASSDB_TYPE_SET_CREDENTIALS);
	req->passdb_callback(req->mech, result);
}

void sasl_server_request_set_credentials(
	struct sasl_server_mech_request *mreq,
	const char *scheme, const char *data,
	sasl_server_mech_passdb_callback_t *callback)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	req->passdb_type = SASL_SERVER_PASSDB_TYPE_SET_CREDENTIALS;
	req->passdb_callback = callback;

	i_assert(funcs->request_set_credentials != NULL);
	funcs->request_set_credentials(req->rctx, scheme, data,
				       set_credentials_callback);
}

struct sasl_server_mech_request *
sasl_server_request_get_mech_request(struct sasl_server_req_ctx *rctx)
{
	return rctx->request->mech;
}
