/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "mech.h"

static int
mech_anonymous_auth_continue(struct auth_request *auth_request,
			     struct auth_login_request_continue *request,
			     const unsigned char *data,
			     mech_callback_t *callback)
{
	i_assert(anonymous_username != NULL);

	if (verbose) {
		i_info("mech-anonymous: login by %s",
		       t_strndup(data, request->data_size));
	}

	auth_request->callback = callback;
	auth_request->user = p_strdup(auth_request->pool, anonymous_username);
	mech_auth_finish(auth_request, NULL, 0, TRUE);
	return TRUE;
}

static void
mech_anonymous_auth_free(struct auth_request *auth_request)
{
	pool_unref(auth_request->pool);
}

static struct auth_request *
mech_anonymous_auth_new(struct login_connection *conn, unsigned int id,
			mech_callback_t *callback)
{
        struct auth_request *auth_request;
	struct auth_login_reply reply;
	pool_t pool;

	pool = pool_alloconly_create("anonymous_auth_request", 256);
	auth_request = p_new(pool, struct auth_request, 1);
	auth_request->pool = pool;
	auth_request->auth_continue = mech_anonymous_auth_continue;
        auth_request->auth_free = mech_anonymous_auth_free;

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = id;
	reply.result = AUTH_LOGIN_RESULT_CONTINUE;

	callback(&reply, NULL, conn);
	return auth_request;
}

struct mech_module mech_anonymous = {
	AUTH_MECH_ANONYMOUS,
	mech_anonymous_auth_new
};
