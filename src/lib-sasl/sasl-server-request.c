/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str-sanitize.h"
#include "buffer.h"

#include "sasl-server-private.h"

/*
 * Public API
 */

void sasl_server_request_create(struct sasl_server_req_ctx *rctx,
				const struct sasl_server_mech *mech,
				const char *protocol,
				struct event *event_parent)
{
	struct sasl_server_instance *sinst = mech->sinst;
	struct sasl_server *server = sinst->server;
	struct sasl_server_request *req;
	pool_t pool;

	i_assert(mech->def != NULL);
	i_assert(mech->def->funcs != NULL);

	i_zero(rctx);

	pool = pool_alloconly_create(
		MEMPOOL_GROWING"sasl_server_request", 2048);
	req = p_new(pool, struct sasl_server_request, 1);
	req->pool = pool;
	req->refcount = 1;
	req->sinst = sinst;
	req->rctx = rctx;

	sinst->requests++;
	server->requests++;

	if (event_parent == NULL) {
		req->event = event_create(sinst->event);
		event_drop_parent_log_prefixes(req->event, 1);
	} else {
		req->event = event_create(event_parent);
		event_add_category(req->event, &event_category_sasl_server);
	}
	event_set_append_log_prefix(req->event,
		t_strdup_printf("sasl(%s): ", t_str_lcase(mech->def->name)));

	struct sasl_server_mech_request *mreq;

	if (mech->def->funcs->auth_new != NULL)
		mreq = mech->def->funcs->auth_new(mech, pool);
	else
		mreq = p_new(pool, struct sasl_server_mech_request, 1);
	mreq->pool = pool;
	mreq->req = req;
	mreq->set = &sinst->set;
	mreq->mech = mech;
	mreq->event = req->event;
	mreq->protocol = p_strdup(pool, protocol);

	req->mech = mreq;
	rctx->mech = mech;
	rctx->mech_name = mech->def->name;
	rctx->request = req;

	e_debug(req->event, "Request create");
}

void sasl_server_mech_request_ref(struct sasl_server_mech_request *mreq)
{
	i_assert(mreq->req->refcount > 0);
	mreq->req->refcount++;
}

void sasl_server_mech_request_unref(struct sasl_server_mech_request **_mreq)
{
	struct sasl_server_mech_request *mreq = *_mreq;

	*_mreq = NULL;
	if (mreq == NULL)
		return;

	struct sasl_server_request *req = mreq->req;

	i_assert(req->refcount > 0);
	if (--req->refcount > 0)
		return;

	struct sasl_server_instance *sinst = req->sinst;
	struct sasl_server *server = sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	i_assert(sinst->requests > 0);
	sinst->requests--;
	i_assert(server->requests > 0);
	server->requests--;

	if (funcs->request_free != NULL && req->rctx != NULL)
		funcs->request_free(req->rctx);
	if (mreq->mech->def->funcs->auth_free != NULL)
		mreq->mech->def->funcs->auth_free(mreq);

	e_debug(req->event, "Request destroy");

	if (req->rctx != NULL)
		i_zero(req->rctx);
	event_unref(&req->event);
	pool_unref(&req->pool);
}

void sasl_server_request_ref(struct sasl_server_req_ctx *rctx)
{
	sasl_server_mech_request_ref(rctx->request->mech);
}

void sasl_server_request_unref(struct sasl_server_req_ctx *rctx)
{
	struct sasl_server_request *req = rctx->request;

	i_zero(rctx);
	if (req == NULL)
		return;

	struct sasl_server_mech_request *mreq = req->mech;

	sasl_server_mech_request_unref(&mreq);
}

void sasl_server_request_destroy(struct sasl_server_req_ctx *rctx)
{
	struct sasl_server_request *req = rctx->request;

	if (req == NULL) {
		i_zero(rctx);
		return;
	}

	req->rctx = NULL;
	sasl_server_request_unref(rctx);
}

static bool
sasl_server_request_fail_on_size(struct sasl_server_request *req,
				 size_t data_size)
{
	if (data_size > (size_t)SASL_MAX_MESSAGE_SIZE) {
		/* We should normally never get here, because the limit enforced
		   by the auth service is smaller.
		 */
		e_debug(req->event, "Excessive response size (> %d)",
			SASL_MAX_MESSAGE_SIZE);
		sasl_server_request_failure(req->mech);
		return TRUE;
	}
	return FALSE;
}

static bool
sasl_server_request_fail_on_nuls(struct sasl_server_request *req,
				 const unsigned char *data, size_t data_size)
{
	const struct sasl_server_mech *mech = req->mech->mech;

	if ((mech->def->flags & SASL_MECH_SEC_ALLOW_NULS) != 0)
		return FALSE;
	if (memchr(data, '\0', data_size) != NULL) {
		e_debug(req->event, "Unexpected NUL in auth data");
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
	const struct sasl_server_mech *mech = mreq->mech;

	i_assert(data != NULL || data_size == 0);

	if (data == NULL) {
		e_debug(req->event,
			"Started interaction without initial response");
	} else {
		e_debug(req->event,
			"Started interaction with initial response (size=%zu)",
			data_size);
	}

	i_assert(req->state == SASL_SERVER_REQUEST_STATE_NEW);
	req->state = SASL_SERVER_REQUEST_STATE_SERVER;

	if (sasl_server_request_fail_on_size(req, data_size))
		return;
	if (sasl_server_request_fail_on_nuls(req, data, data_size))
		return;

	sasl_server_mech_request_ref(mreq);
	i_assert(mech->def->funcs->auth_initial != NULL);
	mech->def->funcs->auth_initial(mreq, data, data_size);
	sasl_server_mech_request_unref(&mreq);
}

void sasl_server_request_input(struct sasl_server_req_ctx *rctx,
			       const unsigned char *data, size_t data_size)
{
	struct sasl_server_request *req = rctx->request;
	struct sasl_server_mech_request *mreq = req->mech;
	const struct sasl_server_mech *mech = mreq->mech;

	i_assert(data != NULL || data_size == 0);

	e_debug(req->event,
		"Client continued interaction with response (size=%zu)",
		data_size);

	if (req->state == SASL_SERVER_REQUEST_STATE_FINISHED &&
	    req->finished_with_data) {
		req->state = SASL_SERVER_REQUEST_STATE_SERVER;
		if (!req->failed)
			sasl_server_request_success(mreq, "", 0);
		else
			sasl_server_request_failure(mreq);
		return;
	}
	i_assert(req->state == SASL_SERVER_REQUEST_STATE_CLIENT);
	i_assert(!req->finished_with_data);
	req->state = SASL_SERVER_REQUEST_STATE_SERVER;

	if (sasl_server_request_fail_on_size(req, data_size))
		return;
	if (sasl_server_request_fail_on_nuls(req, data, data_size))
		return;

	sasl_server_mech_request_ref(mreq);
	i_assert(mech->def->funcs->auth_continue != NULL);
	mech->def->funcs->auth_continue(mreq, data, data_size);
	sasl_server_mech_request_unref(&mreq);
}

bool sasl_server_request_has_failed(const struct sasl_server_req_ctx *rctx)
{
	return rctx->request->failed;
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

	if (strlen(authid) > (size_t)SASL_MAX_AUTHID_SIZE) {
		e_debug(req->event, "Failed to set authid: "
			"Maximum length exceeded (> %d)", SASL_MAX_AUTHID_SIZE);
		req->failed = TRUE;
		return FALSE;
	}

	mreq->authid = p_strdup(req->pool, authid);

	i_assert(req->rctx != NULL);
	i_assert(funcs->request_set_authid != NULL);
	if (!funcs->request_set_authid(req->rctx, authid_type, authid)) {
		e_debug(req->event, "Failed to set authid '%s'",
			str_sanitize(authid, 256));
		req->failed = TRUE;
		return FALSE;
	}

	e_debug(req->event, "Set authid '%s'", str_sanitize(authid, 256));
	return TRUE;
}

bool sasl_server_request_set_authzid(struct sasl_server_mech_request *mreq,
				     const char *authzid)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	if (strlen(authzid) > (size_t)SASL_MAX_AUTHID_SIZE) {
		e_debug(req->event, "Failed to set authzid: "
			"Maximum length exceeded (> %d)", SASL_MAX_AUTHID_SIZE);
		req->failed = TRUE;
		return FALSE;
	}

	i_assert(req->rctx != NULL);
	i_assert(funcs->request_set_authzid != NULL);
	if (!funcs->request_set_authzid(req->rctx, authzid)) {
		e_debug(req->event, "Failed to set authzid '%s'",
			str_sanitize(authzid, 256));
		req->failed = TRUE;
		return FALSE;
	}

	e_debug(req->event, "Set authzid '%s'", str_sanitize(authzid, 256));
	return TRUE;
}

void sasl_server_request_set_realm(struct sasl_server_mech_request *mreq,
				   const char *realm)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	i_assert(mreq->realm == NULL);
	mreq->realm = p_strdup(req->pool, realm);

	i_assert(req->rctx != NULL);
	i_assert(funcs->request_set_realm != NULL);
	funcs->request_set_realm(req->rctx, realm);

	e_debug(req->event, "Set realm '%s'", str_sanitize(realm, 256));
}

bool sasl_server_request_get_extra_field(struct sasl_server_mech_request *mreq,
					 const char *name,
					 const char **field_r)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	i_assert(req->rctx != NULL);
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

	e_debug(req->event, "Request channel binding '%s'",
		str_sanitize(type, 64));

	i_assert(req->rctx != NULL);
	i_assert(funcs->request_start_channel_binding != NULL);
	funcs->request_start_channel_binding(req->rctx, type);
}

int sasl_server_request_accept_channel_binding(
	struct sasl_server_mech_request *mreq, buffer_t **data_r)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;
	int ret;

	i_assert(req->rctx != NULL);
	i_assert(funcs->request_accept_channel_binding != NULL);
	ret = funcs->request_accept_channel_binding(req->rctx, data_r);
	if (ret < 0) {
		e_debug(req->event, "Failed to obtain channel binding data");
		return -1;
	}

	e_debug(req->event, "Obtained channel binding data (size=%zu)",
		(*data_r)->used);
	return 0;
}

void sasl_server_request_output(struct sasl_server_mech_request *mreq,
				const void *data, size_t data_size)
{
	struct sasl_server_request *req = mreq->req;
	struct sasl_server *server = req->sinst->server;
	const struct sasl_server_request_funcs *funcs = server->funcs;

	i_assert(req->rctx != NULL);

	i_assert(!req->failed);
	i_assert(req->state == SASL_SERVER_REQUEST_STATE_NEW ||
		 req->state == SASL_SERVER_REQUEST_STATE_SERVER ||
		 req->state == SASL_SERVER_REQUEST_STATE_PASSDB);
	req->state = SASL_SERVER_REQUEST_STATE_CLIENT;
	req->sequence++;

	e_debug(req->event,
		"Server continued interaction with challenge (size=%zu)",
		data_size);

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

	i_assert(req->rctx != NULL);

	i_assert(!req->failed);
	i_assert(req->state == SASL_SERVER_REQUEST_STATE_NEW ||
		 req->state == SASL_SERVER_REQUEST_STATE_SERVER ||
		 req->state == SASL_SERVER_REQUEST_STATE_PASSDB);
	req->state = SASL_SERVER_REQUEST_STATE_FINISHED;
	req->sequence++;
	if (data_size > 0) {
		e_debug(req->event,
			"Interaction succeeded with final data (size=%zu)",
			data_size);
		i_assert(!req->finished_with_data);
		req->finished_with_data = TRUE;
	} else {
		e_debug(req->event, "Interaction succeeded");
	}

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

	i_assert(req->rctx != NULL);

	i_assert(req->state == SASL_SERVER_REQUEST_STATE_NEW ||
		 req->state == SASL_SERVER_REQUEST_STATE_SERVER ||
		 req->state == SASL_SERVER_REQUEST_STATE_PASSDB);
	req->state = SASL_SERVER_REQUEST_STATE_FINISHED;
	req->sequence++;
	req->failed = TRUE;
	if (data_size > 0) {
		i_assert(status != SASL_SERVER_OUTPUT_INTERNAL_FAILURE);
		i_assert(status != SASL_SERVER_OUTPUT_PASSWORD_MISMATCH);
		i_assert(!req->finished_with_data);
		req->finished_with_data = TRUE;
		e_debug(req->event,
			"Interaction failed with final data (size=%zu)",
			data_size);
	} else if (status == SASL_SERVER_OUTPUT_PASSWORD_MISMATCH) {
		e_debug(req->event, "Interaction failed: Password mismatch");
	} else if (status == SASL_SERVER_OUTPUT_INTERNAL_FAILURE) {
		e_debug(req->event, "Interaction failed (internal failure)");
	} else {
		e_debug(req->event, "Interaction failed");
	}

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

void sasl_server_request_password_mismatch(
	struct sasl_server_mech_request *mreq)
{
	sasl_server_request_failure_common(
		mreq, SASL_SERVER_OUTPUT_PASSWORD_MISMATCH, "", 0);
}

void sasl_server_request_internal_failure(
	struct sasl_server_mech_request *mreq)
{
	sasl_server_request_failure_common(
		mreq, SASL_SERVER_OUTPUT_INTERNAL_FAILURE, "", 0);
}

static const char *
sasl_passdb_result_to_string(enum sasl_passdb_result_status status)
{
	switch (status) {
	case SASL_PASSDB_RESULT_INTERNAL_FAILURE:
		return "internal-failure";
	case SASL_PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		return "scheme-not-available";
	case SASL_PASSDB_RESULT_USER_UNKNOWN:
		return "user-unknown";
	case SASL_PASSDB_RESULT_USER_DISABLED:
		return "scheme-disabled";
	case SASL_PASSDB_RESULT_PASS_EXPIRED:
		return "pass-expired";
	case SASL_PASSDB_RESULT_PASSWORD_MISMATCH:
		return "password-mismatch";
	case SASL_PASSDB_RESULT_OK:
		return "ok";
	}
	i_unreached();
}

static void
verify_plain_callback(struct sasl_server_req_ctx *rctx,
		      const struct sasl_passdb_result *result)
{
	struct sasl_server_request *req = rctx->request;

	i_assert(req->state == SASL_SERVER_REQUEST_STATE_PASSDB);
	req->state = SASL_SERVER_REQUEST_STATE_SERVER;
	if (result->status == SASL_PASSDB_RESULT_INTERNAL_FAILURE)
		req->failed = TRUE;

	e_debug(req->event, "Finished plain passdb verification (status=%s)",
		sasl_passdb_result_to_string(result->status));

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

	i_assert(req->rctx != NULL);

	i_assert(!req->failed);
	i_assert(req->state == SASL_SERVER_REQUEST_STATE_NEW ||
		 req->state == SASL_SERVER_REQUEST_STATE_SERVER);
	req->state = SASL_SERVER_REQUEST_STATE_PASSDB;

	e_debug(req->event, "Performing plain passdb verification");

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

	i_assert(req->state == SASL_SERVER_REQUEST_STATE_PASSDB);
	req->state = SASL_SERVER_REQUEST_STATE_SERVER;
	if (result->status == SASL_PASSDB_RESULT_INTERNAL_FAILURE)
		req->failed = TRUE;

	e_debug(req->event, "Finished passdb credentials lookup (status=%s)",
		sasl_passdb_result_to_string(result->status));

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

	i_assert(req->rctx != NULL);

	i_assert(!req->failed);
	i_assert(req->state == SASL_SERVER_REQUEST_STATE_NEW ||
		 req->state == SASL_SERVER_REQUEST_STATE_SERVER);
	req->state = SASL_SERVER_REQUEST_STATE_PASSDB;

	e_debug(req->event, "Performing passdb credentials lookup (scheme=%s)",
		scheme);

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

	i_assert(req->state == SASL_SERVER_REQUEST_STATE_PASSDB);
	req->state = SASL_SERVER_REQUEST_STATE_SERVER;
	if (result->status == SASL_PASSDB_RESULT_INTERNAL_FAILURE)
		req->failed = TRUE;

	e_debug(req->event, "Finished updating passdb credentials (status=%s)",
		sasl_passdb_result_to_string(result->status));

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

	i_assert(req->rctx != NULL);

	i_assert(!req->failed);
	i_assert(req->state == SASL_SERVER_REQUEST_STATE_NEW ||
		 req->state == SASL_SERVER_REQUEST_STATE_SERVER);
	req->state = SASL_SERVER_REQUEST_STATE_PASSDB;

	e_debug(req->event, "Updating passdb credentials (scheme=%s)",
		scheme);

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

struct sasl_server_req_ctx *
sasl_server_request_get_req_ctx(struct sasl_server_mech_request *mreq)
{
	i_assert(mreq->req->rctx != NULL);
	return mreq->req->rctx;
}
