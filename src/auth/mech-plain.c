/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "safe-memset.h"
#include "mech.h"
#include "passdb.h"

static void verify_callback(enum passdb_result result,
			    struct auth_request *request)
{
	mech_auth_finish(request, NULL, 0, result == PASSDB_RESULT_OK);
}

static int
mech_plain_auth_continue(struct auth_request *auth_request,
			 struct auth_client_request_continue *request,
			 const unsigned char *data, mech_callback_t *callback)
{
	const char *authid, *authenid;
	char *pass;
	size_t i, count, len;

	auth_request->callback = callback;

	/* authorization ID \0 authentication ID \0 pass.
	   we'll ignore authorization ID for now. */
	authid = (const char *) data;
	authenid = NULL; pass = "";

	count = 0;
	for (i = 0; i < request->data_size; i++) {
		if (data[i] == '\0') {
			if (++count == 1)
				authenid = (const char *) data + i+1;
			else {
				i++;
				len = request->data_size - i;
				pass = p_strndup(data_stack_pool, data+i, len);
				break;
			}
		}
	}

	if (authenid == NULL) {
		/* invalid input */
		if (verbose)
			i_info("mech-plain: no username given");
		mech_auth_finish(auth_request, NULL, 0, FALSE);
	} else {
		/* split and save user/realm */
		if (strchr(authenid, '@') == NULL && default_realm != NULL) {
			auth_request->user = p_strconcat(auth_request->pool,
							 authenid, "@",
							 default_realm, NULL);
		} else {
			auth_request->user = p_strdup(auth_request->pool,
						      authenid);
		}

		if (!mech_is_valid_username(auth_request->user)) {
			/* invalid username */
			if (verbose) {
				i_info("mech-plain(%s): invalid username",
				       auth_request->user);
			}
			mech_auth_finish(auth_request, NULL, 0, FALSE);
		} else {
			passdb->verify_plain(auth_request, pass,
					     verify_callback);
		}

		/* make sure it's cleared */
		safe_memset(pass, 0, strlen(pass));
	}
	return TRUE;
}

static void
mech_plain_auth_free(struct auth_request *auth_request)
{
	pool_unref(auth_request->pool);
}

static struct auth_request *
mech_plain_auth_new(struct auth_client_connection *conn, unsigned int id,
		    mech_callback_t *callback)
{
        struct auth_request *auth_request;
	struct auth_client_request_reply reply;
	pool_t pool;

	pool = pool_alloconly_create("plain_auth_request", 256);
	auth_request = p_new(pool, struct auth_request, 1);
	auth_request->pool = pool;
	auth_request->auth_continue = mech_plain_auth_continue;
        auth_request->auth_free = mech_plain_auth_free;

	/* initialize reply */
	memset(&reply, 0, sizeof(reply));
	reply.id = id;
	reply.result = AUTH_CLIENT_RESULT_CONTINUE;

	callback(&reply, NULL, conn);
	return auth_request;
}

struct mech_module mech_plain = {
	AUTH_MECH_PLAIN,
	mech_plain_auth_new
};
