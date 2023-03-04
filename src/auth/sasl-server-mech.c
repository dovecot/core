/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "sasl-server-private.h"

void sasl_server_mech_generic_auth_initial(struct auth_request *request,
					   const unsigned char *data,
					   size_t data_size)
{
	if (data == NULL) {
		sasl_server_request_output(request, uchar_empty_ptr, 0);
	} else {
		/* initial reply given, even if it was 0 bytes */
		request->mech->auth_continue(request, data, data_size);
	}
}

void sasl_server_mech_generic_auth_free(struct auth_request *request)
{
	pool_unref(&request->pool);
}
