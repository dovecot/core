/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "hash.h"
#include "safe-memset.h"
#include "mech.h"
#include "passdb.h"

static int
mech_plain_auth_continue(struct login_connection *conn,
			 struct auth_request *auth_request,
			 struct auth_login_request_continue *request,
			 const unsigned char *data, mech_callback_t *callback)
{
	struct auth_login_reply reply;
	const char *authid, *authenid;
	char *pass;
	void *reply_data = NULL;
	size_t i, count, len;

	memset(&reply, 0, sizeof(reply));
	reply.id = request->id;
	reply.result = AUTH_LOGIN_RESULT_FAILURE;

	/* authorization ID \0 authentication ID \0 pass.
	   we'll ignore authorization ID for now. */
	authid = (const char *) data;
	authenid = NULL; pass = NULL;

	count = 0;
	for (i = 0; i < request->data_size; i++) {
		if (data[i] == '\0') {
			if (++count == 1)
				authenid = data + i+1;
			else {
				i++;
				len = request->data_size - i;
				pass = p_strndup(data_stack_pool, data+i, len);
				break;
			}
		}
	}

	/* split and save user/realm */
	auth_request->user = p_strdup(auth_request->pool, authenid);
	auth_request->realm = strchr(auth_request->user, '@');
	if (auth_request->realm != NULL)
                auth_request->realm++;

	if (pass != NULL) {
		if (passdb->verify_plain(auth_request->user,
					 auth_request->realm,
					 pass) == PASSDB_RESULT_OK) {
			reply_data = mech_auth_success(&reply, auth_request,
						       NULL, 0);
			reply.result = AUTH_LOGIN_RESULT_SUCCESS;
		}

		/* make sure it's cleared */
		safe_memset(pass, 0, strlen(pass));
	}

	callback(&reply, reply_data, conn);
	return reply.result == AUTH_LOGIN_RESULT_SUCCESS;
}

static void
mech_plain_auth_free(struct auth_request *auth_request)
{
	pool_unref(auth_request->pool);
}

static struct auth_request *
mech_plain_auth_new(struct login_connection *conn, unsigned int id,
		    mech_callback_t *callback)
{
        struct auth_request *auth_request;
	struct auth_login_reply reply;
	pool_t pool;

	pool = pool_alloconly_create("plain_auth_request", 256);
	auth_request = p_new(pool, struct auth_request, 1);
	auth_request->pool = pool;
	auth_request->auth_continue = mech_plain_auth_continue;
        auth_request->auth_free = mech_plain_auth_free;

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = id;
	reply.result = AUTH_LOGIN_RESULT_CONTINUE;

	callback(&reply, NULL, conn);
	return auth_request;
}

struct mech_module mech_plain = {
	AUTH_MECH_PLAIN,
	mech_plain_auth_new
};
