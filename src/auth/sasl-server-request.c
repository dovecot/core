/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-request.h"

#include "sasl-server-private.h"

/*
 * Public API
 */

void sasl_server_request_create(struct auth_request *request,
				const struct sasl_server_mech_def *mech,
				struct event *event_parent)
{
	struct sasl_server_mech_request *mreq;
	pool_t pool;

	pool = request->pool;
	if (mech->auth_new != NULL)
		mreq = mech->auth_new(pool);
	else
		mreq = p_new(pool, struct sasl_server_mech_request, 1);
	mreq->pool = pool;
	mreq->request = request;
	mreq->mech = mech;
	mreq->mech_event = event_parent;

	request->sasl = mreq;
}

void sasl_server_request_destroy(struct auth_request *request)
{
	struct sasl_server_mech_request *mreq = request->sasl;

	if (mreq == NULL)
		return;
	request->sasl = NULL;

	if (mreq->mech->auth_free != NULL)
		mreq->mech->auth_free(mreq);
}

/*
 * Mechanism API
 */

bool sasl_server_request_set_authid(struct sasl_server_mech_request *mreq,
				    enum sasl_server_authid_type authid_type,
				    const char *authid)
{
	struct auth_request *request = mreq->request;

	return auth_sasl_request_set_authid(request, authid_type, authid);
}

bool sasl_server_request_set_authzid(struct sasl_server_mech_request *mreq,
				     const char *authzid)
{
	struct auth_request *request = mreq->request;

	return auth_sasl_request_set_authzid(request, authzid);
}

void sasl_server_request_set_realm(struct sasl_server_mech_request *mreq,
				   const char *realm)
{
	struct auth_request *request = mreq->request;

	auth_sasl_request_set_realm(request, realm);
}

bool sasl_server_request_get_extra_field(struct sasl_server_mech_request *mreq,
					 const char *name,
					 const char **field_r)
{
	struct auth_request *request = mreq->request;

	return auth_sasl_request_get_extra_field(request, name, field_r);
}

void sasl_server_request_start_channel_binding(
	struct sasl_server_mech_request *mreq, const char *type)
{
	struct auth_request *request = mreq->request;

	auth_sasl_request_start_channel_binding(request, type);
}

int sasl_server_request_accept_channel_binding(
	struct sasl_server_mech_request *mreq, buffer_t **data_r)
{
	struct auth_request *request = mreq->request;

	return auth_sasl_request_accept_channel_binding(request, data_r);
}

void sasl_server_request_output(struct sasl_server_mech_request *mreq,
				const void *data, size_t data_size)
{
	struct auth_request *request = mreq->request;

	const struct sasl_server_output output = {
		.status = SASL_SERVER_OUTPUT_CONTINUE,
		.data = data,
		.data_size = data_size,
	};
	auth_sasl_request_output(request, &output);
}

void sasl_server_request_success(struct sasl_server_mech_request *mreq,
				 const void *data, size_t data_size)
{
	struct auth_request *request = mreq->request;

	const struct sasl_server_output output = {
		.status = SASL_SERVER_OUTPUT_SUCCESS,
		.data = data,
		.data_size = data_size,
	};
	auth_sasl_request_output(request, &output);
}

static void
sasl_server_request_failure_common(struct sasl_server_mech_request *mreq,
				   enum sasl_server_output_status status,
				   const void *data, size_t data_size)
{
	struct auth_request *request = mreq->request;

	const struct sasl_server_output output = {
		.status = status,
		.data = data,
		.data_size = data_size,
	};
	auth_sasl_request_output(request, &output);
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
verify_plain_callback(enum passdb_result result, struct auth_request *request)
{
	struct sasl_server_mech_request *mreq = request->sasl;

	mreq->private_callback.verify_plain(result, request->sasl);
}

void sasl_server_request_verify_plain(
	struct sasl_server_mech_request *mreq, const char *password,
	sasl_server_verify_plain_callback_t *callback)
{
	struct auth_request *request = mreq->request;

	mreq->private_callback.verify_plain = callback;
	auth_sasl_request_verify_plain(request, password, verify_plain_callback);
}

static void
lookup_credentials_callback(enum passdb_result result,
			    const unsigned char *credentials,
			    size_t size, struct auth_request *request)
{
	struct sasl_server_mech_request *mreq = request->sasl;

	mreq->private_callback.lookup_credentials(result, credentials, size,
						  mreq);
}

void sasl_server_request_lookup_credentials(
	struct sasl_server_mech_request *mreq, const char *scheme,
	sasl_server_lookup_credentials_callback_t *callback)
{
	struct auth_request *request = mreq->request;

	mreq->private_callback.lookup_credentials = callback;
	auth_sasl_request_lookup_credentials(request, scheme, 
					     lookup_credentials_callback);
}

static void
set_credentials_callback(bool success, struct auth_request *request)
{
	struct sasl_server_mech_request *mreq = request->sasl;

	mreq->private_callback.set_credentials(success, mreq);
}

void sasl_server_request_set_credentials(
	struct sasl_server_mech_request *mreq,
	const char *scheme, const char *data,
	sasl_server_set_credentials_callback_t *callback)
{
	struct auth_request *request = mreq->request;

	mreq->private_callback.set_credentials = callback;
	auth_sasl_request_set_credentials(request, scheme, data,
					  set_credentials_callback);
}
