/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "mech.h"

static int
mech_anonymous_auth_continue(struct auth_request *auth_request,
			     const unsigned char *data, size_t data_size,
			     mech_callback_t *callback)
{
	i_assert(anonymous_username != NULL);

	if (verbose) {
		i_info("mech-anonymous: login by %s",
		       t_strndup(data, data_size));
	}

	auth_request->callback = callback;
	auth_request->user = p_strdup(auth_request->pool, anonymous_username);
	mech_auth_finish(auth_request, NULL, 0, TRUE);
	return TRUE;
}

static int
mech_anonymous_auth_initial(struct auth_request *auth_request,
			    struct auth_client_request_new *request,
			    const unsigned char *data,
			    mech_callback_t *callback)
{
	struct auth_client_request_reply reply;
	size_t data_size;

	if (AUTH_CLIENT_REQUEST_HAVE_INITIAL_RESPONSE(request)) {
		data += request->initial_resp_idx;
		data_size = request->data_size - request->initial_resp_idx;

		return auth_request->auth_continue(auth_request, data,
						   data_size, callback);
	}

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = auth_request->id;
	reply.result = AUTH_CLIENT_RESULT_CONTINUE;

	callback(&reply, NULL, auth_request->conn);
	return TRUE;
}

static void
mech_anonymous_auth_free(struct auth_request *auth_request)
{
	pool_unref(auth_request->pool);
}

static struct auth_request *mech_anonymous_auth_new(void)
{
        struct auth_request *auth_request;
	pool_t pool;

	pool = pool_alloconly_create("anonymous_auth_request", 256);
	auth_request = p_new(pool, struct auth_request, 1);
	auth_request->refcount = 1;
	auth_request->pool = pool;
	auth_request->auth_initial = mech_anonymous_auth_initial;
	auth_request->auth_continue = mech_anonymous_auth_continue;
        auth_request->auth_free = mech_anonymous_auth_free;

	return auth_request;
}

struct mech_module mech_anonymous = {
	"ANONYMOUS",

	MEMBER(plaintext) FALSE,
	MEMBER(advertise) TRUE,

	MEMBER(passdb_need_plain) FALSE,
	MEMBER(passdb_need_credentials) FALSE,

	mech_anonymous_auth_new
};
