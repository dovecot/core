/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "sasl-server-protected.h"
#include "sasl-server-mech-plain-common.h"

void sasl_server_mech_plain_verify_callback(enum passdb_result result,
					    struct auth_request *request)
{
	switch (result) {
	case SASL_PASSDB_RESULT_OK:
		sasl_server_request_success(request, "", 0);
		break;
	case SASL_PASSDB_RESULT_INTERNAL_FAILURE:
		sasl_server_request_internal_failure(request);
		break;
	default:
		sasl_server_request_failure(request);
		break;
	}
}
