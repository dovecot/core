/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "sasl-server-private.h"

void sasl_server_mech_generic_auth_initial(
	struct sasl_server_mech_request *mreq,
	const unsigned char *data, size_t data_size)
{
	struct auth_request *request = mreq->request;

	if (data == NULL) {
		sasl_server_request_output(mreq, uchar_empty_ptr, 0);
	} else {
		/* initial reply given, even if it was 0 bytes */
		request->mech->auth_continue(mreq, data, data_size);
	}
}
