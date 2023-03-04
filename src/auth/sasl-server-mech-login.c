/*
 * LOGIN authentication mechanism.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "safe-memset.h"

#include "sasl-server-protected.h"
#include "sasl-server-mech-plain-common.h"

static void
mech_login_auth_continue(struct auth_request *request,
			 const unsigned char *data, size_t data_size)
{
	static const char prompt2[] = "Password:";
	const char *username, *error;

	if (request->fields.user == NULL) {
		username = t_strndup(data, data_size);

		if (!auth_request_set_username(request, username, &error)) {
                        e_info(request->mech_event, "%s", error);
			auth_request_fail(request);
			return;
		}

		sasl_server_request_output(request, prompt2, strlen(prompt2));
	} else {
		char *pass = p_strndup(unsafe_data_stack_pool, data, data_size);
		auth_request_verify_plain(
			request, pass, sasl_server_mech_plain_verify_callback);
		safe_memset(pass, 0, strlen(pass));
	}
}

static void
mech_login_auth_initial(struct auth_request *request,
			const unsigned char *data, size_t data_size)
{
	static const char prompt1[] = "Username:";

	if (data_size == 0) {
		sasl_server_request_output(request, prompt1, strlen(prompt1));
	} else {
		mech_login_auth_continue(request, data, data_size);
	}
}

static struct auth_request *mech_login_auth_new(void)
{
	struct auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"login_auth_request", 2048);
	request = p_new(pool, struct auth_request, 1);
	request->pool = pool;
	return request;
}

const struct mech_module mech_login = {
	.mech_name = "LOGIN",

	.flags = MECH_SEC_PLAINTEXT,
	.passdb_need = MECH_PASSDB_NEED_VERIFY_PLAIN,

	.auth_new = mech_login_auth_new,
	.auth_initial = mech_login_auth_initial,
	.auth_continue = mech_login_auth_continue,
	.auth_free = sasl_server_mech_generic_auth_free,
};
