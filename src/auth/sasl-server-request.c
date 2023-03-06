/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-request.h"

#include "sasl-server-private.h"

/*
 * Mechanism API
 */

bool sasl_server_request_set_authid(struct auth_request *request,
				    enum sasl_server_authid_type authid_type,
				    const char *authid)
{
	return auth_sasl_request_set_authid(request, authid_type, authid);
}

bool sasl_server_request_set_authzid(struct auth_request *request,
				     const char *authzid)
{
	return auth_sasl_request_set_authzid(request, authzid);
}

void sasl_server_request_set_realm(struct auth_request *request,
				   const char *realm)
{
	auth_sasl_request_set_realm(request, realm);
}

bool sasl_server_request_get_extra_field(struct auth_request *request,
					 const char *name,
					 const char **field_r)
{
	return auth_sasl_request_get_extra_field(request, name, field_r);
}

void sasl_server_request_start_channel_binding(
	struct auth_request *request, const char *type)
{
	auth_sasl_request_start_channel_binding(request, type);
}

int sasl_server_request_accept_channel_binding(
	struct auth_request *request, buffer_t **data_r)
{
	return auth_sasl_request_accept_channel_binding(request, data_r);
}

void sasl_server_request_output(struct auth_request *request,
				const void *data, size_t data_size)
{
	const struct sasl_server_output output = {
		.status = SASL_SERVER_OUTPUT_CONTINUE,
		.data = data,
		.data_size = data_size,
	};
	auth_sasl_request_output(request, &output);
}

void sasl_server_request_success(struct auth_request *request,
				 const void *data, size_t data_size)
{
	const struct sasl_server_output output = {
		.status = SASL_SERVER_OUTPUT_SUCCESS,
		.data = data,
		.data_size = data_size,
	};
	auth_sasl_request_output(request, &output);
}

static void
sasl_server_request_failure_common(struct auth_request *request,
				   enum sasl_server_output_status status,
				   const void *data, size_t data_size)
{
	const struct sasl_server_output output = {
		.status = status,
		.data = data,
		.data_size = data_size,
	};
	auth_sasl_request_output(request, &output);
}

void sasl_server_request_failure_with_reply(struct auth_request *request,
					    const void *data, size_t data_size)
{
	sasl_server_request_failure_common(request, SASL_SERVER_OUTPUT_FAILURE,
					   data, data_size);
}

void sasl_server_request_failure(struct auth_request *request)
{
	sasl_server_request_failure_common(request, SASL_SERVER_OUTPUT_FAILURE,
					   "", 0);
}

void sasl_server_request_internal_failure(struct auth_request *request)
{
	sasl_server_request_failure_common(request,
					   SASL_SERVER_OUTPUT_INTERNAL_FAILURE,
					   "", 0);
}

void sasl_server_request_verify_plain(
	struct auth_request *request, const char *password,
	sasl_server_verify_plain_callback_t *callback)
{
	auth_sasl_request_verify_plain(request, password, callback);
}

void sasl_server_request_lookup_credentials(
	struct auth_request *request, const char *scheme,
	sasl_server_lookup_credentials_callback_t *callback)
{
	auth_sasl_request_lookup_credentials(request, scheme, callback);
}

void sasl_server_request_set_credentials(
	struct auth_request *request, const char *scheme, const char *data,
	sasl_server_set_credentials_callback_t *callback)
{
	auth_sasl_request_set_credentials(request, scheme, data, callback);
}
