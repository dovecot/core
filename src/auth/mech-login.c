/*
 * LOGIN authentication mechanism.
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
#include "safe-memset.h"

static void verify_callback(enum passdb_result result,
			    struct auth_request *request)
{
	mech_auth_finish(request, NULL, 0, result == PASSDB_RESULT_OK);
}

static int
mech_login_auth_continue(struct auth_request *auth_request,
			 const unsigned char *data, size_t data_size,
			 mech_callback_t *callback)
{
	struct auth_client_request_reply reply;
	static const char prompt2[] = "Password:";
	const char *error;

	auth_request->callback = callback;

	if (!auth_request->user) {
		auth_request->user =
			p_strndup(auth_request->pool, data, data_size);

		if (!mech_fix_username(auth_request->user, &error)) {
			if (verbose) {
				i_info("login(%s): %s",
				       get_log_prefix(auth_request), error);
			}
			mech_auth_finish(auth_request, NULL, 0, FALSE);
			return TRUE;
		}

		mech_init_auth_client_reply(&reply);
		reply.id = auth_request->id;
		reply.result = AUTH_CLIENT_RESULT_CONTINUE;

		reply.reply_idx = 0;
		reply.data_size = strlen(prompt2);
		callback(&reply, prompt2, auth_request->conn);
	} else {
		char *pass = p_strndup(unsafe_data_stack_pool, data, data_size);

		passdb->verify_plain(auth_request, pass, verify_callback);

		safe_memset(pass, 0, strlen(pass));
	}

	return TRUE;
}

static int
mech_login_auth_initial(struct auth_request *auth_request,
		       struct auth_client_request_new *request,
		       const unsigned char *data __attr_unused__,
		       mech_callback_t *callback)
{
	struct auth_client_request_reply reply;
	static const char prompt1[] = "Username:";

	mech_init_auth_client_reply(&reply);
	reply.id = request->id;
	reply.result = AUTH_CLIENT_RESULT_CONTINUE;

	reply.reply_idx = 0;
	reply.data_size = strlen(prompt1);
	callback(&reply, prompt1, auth_request->conn);

	return TRUE;
}

static void mech_login_auth_free(struct auth_request *auth_request)
{
	pool_unref(auth_request->pool);
}

static struct auth_request *mech_login_auth_new(void)
{
	struct auth_request *auth;
	pool_t pool;

	pool = pool_alloconly_create("login_auth_request", 256);
	auth = p_new(pool, struct auth_request, 1);

	auth->refcount = 1;
	auth->pool = pool;
	auth->auth_initial = mech_login_auth_initial;
	auth->auth_continue = mech_login_auth_continue;
	auth->auth_free = mech_login_auth_free;

	return auth;
}

const struct mech_module mech_login = {
	"LOGIN",

	MEMBER(plaintext) TRUE,
	MEMBER(advertise) TRUE,

	MEMBER(passdb_need_plain) TRUE,
	MEMBER(passdb_need_credentials) FALSE,

	mech_login_auth_new,
};
