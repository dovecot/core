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
			 const unsigned char *data, size_t data_size,
			 mech_callback_t *callback)
{
	const char *authid, *authenid, *error;
	char *pass;
	size_t i, count, len;

	auth_request->callback = callback;

	/* authorization ID \0 authentication ID \0 pass.
	   we'll ignore authorization ID for now. */
	authid = (const char *) data;
	authenid = NULL; pass = "";

	count = 0;
	for (i = 0; i < data_size; i++) {
		if (data[i] == '\0') {
			if (++count == 1)
				authenid = (const char *) data + i+1;
			else {
				i++;
				len = data_size - i;
				pass = p_strndup(unsafe_data_stack_pool,
						 data+i, len);
				break;
			}
		}
	}

	if (count != 2) {
		/* invalid input */
		if (verbose) {
			i_info("plain(%s): invalid input",
			       get_log_prefix(auth_request));
		}
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

		if (!mech_fix_username(auth_request->user, &error)) {
			/* invalid username */
			if (verbose) {
				i_info("plain(%s): %s",
				       get_log_prefix(auth_request), error);
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

static int
mech_plain_auth_initial(struct auth_request *auth_request,
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
	reply.id = request->id;
	reply.result = AUTH_CLIENT_RESULT_CONTINUE;

	callback(&reply, NULL, auth_request->conn);
	return TRUE;
}

static void
mech_plain_auth_free(struct auth_request *auth_request)
{
	pool_unref(auth_request->pool);
}

static struct auth_request *mech_plain_auth_new(void)
{
        struct auth_request *auth_request;
	pool_t pool;

	pool = pool_alloconly_create("plain_auth_request", 256);
	auth_request = p_new(pool, struct auth_request, 1);
	auth_request->refcount = 1;
	auth_request->pool = pool;
	auth_request->auth_initial = mech_plain_auth_initial;
	auth_request->auth_continue = mech_plain_auth_continue;
        auth_request->auth_free = mech_plain_auth_free;
	return auth_request;
}

struct mech_module mech_plain = {
	"PLAIN",

	MEMBER(plaintext) TRUE,
	MEMBER(advertise) FALSE,

	MEMBER(passdb_need_plain) TRUE,
	MEMBER(passdb_need_credentials) FALSE,

	mech_plain_auth_new
};
