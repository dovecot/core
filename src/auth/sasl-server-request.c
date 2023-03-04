/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-request.h"

#include "sasl-server-private.h"

/*
 * Mechanism API
 */

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

void sasl_server_request_failure_with_reply(struct auth_request *request,
					    const void *data, size_t data_size)
{
	const struct sasl_server_output output = {
		.status = SASL_SERVER_OUTPUT_FAILURE,
		.data = data,
		.data_size = data_size,
	};
	auth_sasl_request_output(request, &output);
}

void sasl_server_request_failure(struct auth_request *request)
{
	sasl_server_request_failure_with_reply(request, "", 0);
}
