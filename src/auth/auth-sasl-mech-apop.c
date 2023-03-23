/*
 * APOP (RFC-1460) authentication mechanism.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "passdb.h"
#include "md5.h"
#include "buffer.h"
#include "sasl-server-protected.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <stdio.h>
#include <unistd.h>

struct apop_auth_request {
	struct sasl_server_mech_request auth_request;

	/* requested: */
	char *challenge;

	/* received: */
	unsigned char response_digest[16];
};

static bool verify_credentials(struct apop_auth_request *request,
			       const unsigned char *credentials, size_t size)
{
	unsigned char digest[16];
	struct md5_context ctx;

	md5_init(&ctx);
	md5_update(&ctx, request->challenge, strlen(request->challenge));
	md5_update(&ctx, credentials, size);
	md5_final(&ctx, digest);

	return mem_equals_timing_safe(digest, request->response_digest, 16);
}

static void
apop_credentials_callback(struct sasl_server_mech_request *auth_request,
			  const struct sasl_passdb_result *result)
{
	struct apop_auth_request *request =
		container_of(auth_request, struct apop_auth_request,
			     auth_request);

	switch (result->status) {
	case SASL_PASSDB_RESULT_OK:
		if (verify_credentials(request, result->credentials.data,
				       result->credentials.size))
			sasl_server_request_success(auth_request, "", 0);
		else
			sasl_server_request_failure(auth_request);
		break;
	case SASL_PASSDB_RESULT_INTERNAL_FAILURE:
		sasl_server_request_internal_failure(auth_request);
		break;
	default:
		sasl_server_request_failure(auth_request);
		break;
	}
}

static void
mech_apop_auth_initial(struct sasl_server_mech_request *auth_request,
		       const unsigned char *data, size_t data_size)
{
	struct apop_auth_request *request =
		container_of(auth_request, struct apop_auth_request,
			     auth_request);
	const unsigned char *tmp, *end, *username = NULL;
	unsigned long pid, connect_uid, timestamp;

	/* pop3-login handles sending the challenge and getting the response.
	   Our input here is: <challenge> \0 <username> \0 <response> */

	if (data_size == 0) {
		/* Should never happen */
		e_info(auth_request->mech_event,
		       "no initial response");
		sasl_server_request_failure(auth_request);
		return;
	}

	tmp = data;
	end = data + data_size;

	/* get the challenge */
	while (tmp != end && *tmp != '\0')
		tmp++;
	request->challenge = p_strdup_until(auth_request->pool, data, tmp);

	if (tmp != end) {
		/* get the username */
		username = ++tmp;
		while (tmp != end && *tmp != '\0')
			tmp++;
	} else {
		/* should never happen */
		e_info(auth_request->mech_event,
		       "malformed data");
		sasl_server_request_failure(auth_request);
		return;
	}

	if (tmp + 1 + 16 != end) {
		/* Should never happen */
		e_info(auth_request->mech_event,
		       "malformed data");
		sasl_server_request_failure(auth_request);
		return;
	}
	memcpy(request->response_digest, tmp + 1,
	       sizeof(request->response_digest));

	/* the challenge must begin with trusted unique ID. we trust only
	   ourself, so make sure it matches our connection specific UID
	   which we told to client in handshake. Also require a timestamp
	   which is later than this process's start time. */

	if (sscanf(request->challenge, "<%lx.%lx.%lx.",
		   &pid, &connect_uid, &timestamp) != 3 ||
	    connect_uid != auth_request->request->connect_uid ||
            pid != (unsigned long)getpid() ||
	    (time_t)timestamp < process_start_time) {
		e_info(auth_request->mech_event,
		       "invalid challenge");
		sasl_server_request_failure(auth_request);
		return;
	}

	if (!sasl_server_request_set_authid(auth_request,
					    SASL_SERVER_AUTHID_TYPE_USERNAME,
					    (const char *)username)) {
		sasl_server_request_failure(auth_request);
		return;
	}

	sasl_server_request_lookup_credentials(auth_request, "PLAIN",
					       apop_credentials_callback);
}

static struct sasl_server_mech_request *mech_apop_auth_new(pool_t pool)
{
	struct apop_auth_request *request;

	request = p_new(pool, struct apop_auth_request, 1);

	return &request->auth_request;
}

static const struct sasl_server_mech_funcs mech_apop_funcs = {
	.auth_new = mech_apop_auth_new,
	.auth_initial = mech_apop_auth_initial,
};

const struct sasl_server_mech_def mech_apop = {
	.mech_name = "APOP",

	.flags = SASL_MECH_SEC_PRIVATE | SASL_MECH_SEC_DICTIONARY |
		 SASL_MECH_SEC_ACTIVE | SASL_MECH_SEC_ALLOW_NULS,
	.passdb_need = SASL_MECH_PASSDB_NEED_VERIFY_RESPONSE,

	.funcs = &mech_apop_funcs,
};
