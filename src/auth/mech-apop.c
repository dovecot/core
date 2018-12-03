/*
 * APOP (RFC-1460) authentication mechanism.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "mech.h"
#include "passdb.h"
#include "md5.h"
#include "buffer.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <stdio.h>
#include <unistd.h>

struct apop_auth_request {
	struct auth_request auth_request;

	pool_t pool;

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
apop_credentials_callback(enum passdb_result result,
			  const unsigned char *credentials, size_t size,
			  struct auth_request *auth_request)
{
	struct apop_auth_request *request =
		(struct apop_auth_request *)auth_request;

	switch (result) {
	case PASSDB_RESULT_OK:
		if (verify_credentials(request, credentials, size))
			auth_request_success(auth_request, "", 0);
		else
			auth_request_fail(auth_request);
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(auth_request);
		break;
	default:
		auth_request_fail(auth_request);
		break;
	}
}

static void
mech_apop_auth_initial(struct auth_request *auth_request,
		       const unsigned char *data, size_t data_size)
{
	struct apop_auth_request *request =
		(struct apop_auth_request *)auth_request;
	const unsigned char *tmp, *end, *username = NULL;
	unsigned long pid, connect_uid, timestamp;
	const char *error;

	/* pop3-login handles sending the challenge and getting the response.
	   Our input here is: <challenge> \0 <username> \0 <response> */

	if (data_size == 0) {
		/* Should never happen */
		e_info(auth_request->mech_event,
		       "no initial response");
		auth_request_fail(auth_request);
		return;
	}

	tmp = data;
	end = data + data_size;

	/* get the challenge */
	while (tmp != end && *tmp != '\0')
		tmp++;
	request->challenge = p_strdup_until(request->pool, data, tmp);

	if (tmp != end) {
		/* get the username */
		username = ++tmp;
		while (tmp != end && *tmp != '\0')
			tmp++;
	} else {
		/* should never happen */
		e_info(auth_request->mech_event,
		       "malformed data");
		auth_request_fail(auth_request);
		return;
	}

	if (tmp + 1 + 16 != end) {
		/* Should never happen */
		e_info(auth_request->mech_event,
		       "malformed data");
		auth_request_fail(auth_request);
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
	    connect_uid != auth_request->connect_uid ||
            pid != (unsigned long)getpid() ||
	    (time_t)timestamp < process_start_time) {
		e_info(auth_request->mech_event,
		       "invalid challenge");
		auth_request_fail(auth_request);
		return;
	}

	if (!auth_request_set_username(auth_request, (const char *)username,
				       &error)) {
		e_info(auth_request->mech_event, "%s", error);
		auth_request_fail(auth_request);
		return;
	}

	auth_request_lookup_credentials(auth_request, "PLAIN",
					apop_credentials_callback);
}

static struct auth_request *mech_apop_auth_new(void)
{
	struct apop_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"apop_auth_request", 2048);
	request = p_new(pool, struct apop_auth_request, 1);
	request->pool = pool;

	request->auth_request.pool = pool;
	return &request->auth_request;
}

const struct mech_module mech_apop = {
	"APOP",

	.flags = MECH_SEC_PRIVATE | MECH_SEC_DICTIONARY | MECH_SEC_ACTIVE,
	.passdb_need = MECH_PASSDB_NEED_VERIFY_RESPONSE,

	mech_apop_auth_new,
	mech_apop_auth_initial,
	NULL,
        mech_generic_auth_free
};
