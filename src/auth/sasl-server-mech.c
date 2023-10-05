/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "sasl-server-private.h"

void mech_generic_auth_initial(struct auth_request *request,
			       const unsigned char *data, size_t data_size)
{
	if (data == NULL) {
		auth_request_handler_reply_continue(request, uchar_empty_ptr, 0);
	} else {
		/* initial reply given, even if it was 0 bytes */
		request->mech->auth_continue(request, data, data_size);
	}
}
