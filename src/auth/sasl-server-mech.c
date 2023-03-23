/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "sasl-server-private.h"

void sasl_server_mech_generic_auth_initial(
	struct sasl_server_mech_request *mreq,
	const unsigned char *data, size_t data_size)
{
	const struct sasl_server_mech_def *mech = mreq->mech;

	if (data == NULL) {
		sasl_server_request_output(mreq, uchar_empty_ptr, 0);
	} else {
		/* initial reply given, even if it was 0 bytes */
		i_assert(mech->funcs->auth_continue != NULL);
		mech->funcs->auth_continue(mreq, data, data_size);
	}
}
