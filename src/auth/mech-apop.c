/*
 * APOP (RFC-1460) authentication mechanism.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published 
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "common.h"
#include "mech.h"
#include "passdb.h"
#include "md5.h"
#include "buffer.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <ctype.h>

struct apop_auth_request {
	struct auth_request auth_request;

	pool_t pool;

	/* requested: */
	char *challenge;

	/* received: */
	unsigned char digest[16];
};

static void
apop_credentials_callback(const char *credentials,
			  struct auth_request *auth_request)
{
	struct apop_auth_request *auth =
		(struct apop_auth_request *)auth_request;
	unsigned char digest[16];
	struct md5_context ctx;
	int ret = FALSE;

	if (credentials != NULL) {
		md5_init(&ctx);
		md5_update(&ctx, auth->challenge, strlen(auth->challenge));
		md5_update(&ctx, credentials, strlen(credentials));
		md5_final(&ctx, digest);

		ret = memcmp(digest, auth->digest, 16) == 0;
	}

	mech_auth_finish(auth_request, NULL, 0, ret);
}

static int
mech_apop_auth_initial(struct auth_request *auth_request,
		       struct auth_client_request_new *request,
		       const unsigned char *data,
		       mech_callback_t *callback)
{
	struct apop_auth_request *auth =
		(struct apop_auth_request *)auth_request;
	const unsigned char *tmp, *end, *username = NULL;
	const char *str;

	auth_request->callback = callback;

	if (!AUTH_CLIENT_REQUEST_HAVE_INITIAL_RESPONSE(request)) {
		/* Should never happen */
		if (verbose) {
			i_info("apop(%s): no initial respone",
			       get_log_prefix(auth_request));
		}
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return TRUE;
	}

	tmp = data = data + request->initial_resp_idx;
	end = data + request->data_size - request->initial_resp_idx;

	while (tmp != end && *tmp != '\0')
		tmp++;

	/* the challenge must begin with trusted unique ID. we trust only
	   ourself, so make sure it matches our connection specific UID
	   which we told to client in handshake. */
        str = t_strdup_printf("<%x.%x.", auth_request->conn->master->pid,
			      auth_request->conn->connect_uid);
	if (memcmp(data, str, strlen(str)) != 0) {
		if (verbose) {
			i_info("apop(%s): invalid challenge",
			       get_log_prefix(auth_request));
		}
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return TRUE;
	}
	auth->challenge = p_strdup(auth->pool, data);

	if (tmp != end) {
		username = ++tmp;
		while (tmp != end && *tmp != '\0')
			tmp++;
	}

	if (tmp + 1 + 16 != end) {
		/* Should never happen */
		if (verbose) {
			i_info("apop(%s): malformed data",
			       get_log_prefix(auth_request));
		}
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return TRUE;
	}
	tmp++;

	auth_request->user = p_strdup(auth->pool, username);
	if (!mech_fix_username(auth_request->user)) {
		if (verbose) {
			i_info("apop(%s): invalid username",
			       get_log_prefix(auth_request));
		}
		mech_auth_finish(auth_request, NULL, 0, FALSE);
		return TRUE;
	}

	memcpy(auth->digest, tmp, sizeof(auth->digest));

	passdb->lookup_credentials(auth_request, PASSDB_CREDENTIALS_PLAINTEXT,
				   apop_credentials_callback);
	return TRUE;
}

static void mech_apop_auth_free(struct auth_request *auth_request)
{
	pool_unref(auth_request->pool);
}

static struct auth_request *mech_apop_auth_new(void)
{
	struct apop_auth_request *auth;
	pool_t pool;

	pool = pool_alloconly_create("apop_auth_request", 256);
	auth = p_new(pool, struct apop_auth_request, 1);
	auth->pool = pool;

	auth->auth_request.refcount = 1;
	auth->auth_request.pool = pool;
	auth->auth_request.auth_initial = mech_apop_auth_initial;
	auth->auth_request.auth_continue = NULL;
	auth->auth_request.auth_free = mech_apop_auth_free;

	return &auth->auth_request;
}

const struct mech_module mech_apop = {
	"APOP",

	MEMBER(plaintext) FALSE,
	MEMBER(advertise) FALSE,

	MEMBER(passdb_need_plain) FALSE,
	MEMBER(passdb_need_credentials) TRUE,

	mech_apop_auth_new,
};
