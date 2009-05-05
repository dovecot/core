#include "auth-common.h"
#include "mech.h"
#include "passdb.h"
#include "mech-plain-common.h"

void plain_verify_callback(enum passdb_result result,
			   struct auth_request *request)
{
	switch (result) {
	case PASSDB_RESULT_OK:
		auth_request_success(request, NULL, 0);
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(request);
		break;
	default:
		auth_request_fail(request);
		break;
	}
}
