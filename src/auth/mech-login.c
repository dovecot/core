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

static void
mech_login_auth_continue(struct auth_request *request,
			 const unsigned char *data, size_t data_size)
{
	static const char prompt2[] = "Password:";
	const char *username, *error;

	if (request->user == NULL) {
		username = t_strndup(data, data_size);

		if (!auth_request_set_username(request, username, &error)) {
                        auth_request_log_info(request, "login", "%s", error);
			auth_request_fail(request);
			return;
		}

		request->callback(request, AUTH_CLIENT_RESULT_CONTINUE,
				  prompt2, strlen(prompt2));
	} else {
		char *pass = p_strndup(unsafe_data_stack_pool, data, data_size);
		auth_request_verify_plain(request, pass, verify_callback);
		safe_memset(pass, 0, strlen(pass));
	}
}

static void
mech_login_auth_initial(struct auth_request *request,
			const unsigned char *data, size_t data_size)
{
	static const char prompt1[] = "Username:";

	if (data_size == 0) {
		request->callback(request, AUTH_CLIENT_RESULT_CONTINUE,
				  prompt1, strlen(prompt1));
	} else {
		mech_login_auth_continue(request, data, data_size);
	}
}

static void mech_login_auth_free(struct auth_request *request)
{
	pool_unref(request->pool);
}

static struct auth_request *mech_login_auth_new(void)
{
	struct auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create("login_auth_request", 1024);
	request = p_new(pool, struct auth_request, 1);
	request->pool = pool;
	return request;
}

const struct mech_module mech_login = {
	"LOGIN",

	MEMBER(flags) MECH_SEC_PLAINTEXT,

	MEMBER(passdb_need_plain) TRUE,
	MEMBER(passdb_need_credentials) FALSE,

	mech_login_auth_new,
	mech_login_auth_initial,
	mech_login_auth_continue,
        mech_login_auth_free
};
