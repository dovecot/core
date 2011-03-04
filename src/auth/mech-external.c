/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"
#include "mech.h"
#include "mech-plain-common.h"

static void
mech_external_auth_continue(struct auth_request *request,
			    const unsigned char *data, size_t data_size)
{
	const char *authzid, *error;

	authzid = t_strndup(data, data_size);
	if (request->user == NULL) {
		auth_request_log_info(request, "external",
				      "username not known");
		auth_request_fail(request);
        } else if (*authzid != '\0' &&
		   !auth_request_set_login_username(request, authzid, &error)) {
		/* invalid login username */
		auth_request_log_info(request, "plain",
				      "login user: %s", error);
		auth_request_fail(request);
	} else {
                auth_request_verify_plain(request, "",
                                          plain_verify_callback);
	}
}

static struct auth_request *mech_external_auth_new(void)
{
        struct auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create("external_auth_request", 2048);
	request = p_new(pool, struct auth_request, 1);
	request->pool = pool;
	return request;
}

const struct mech_module mech_external = {
	"EXTERNAL",

	.flags = 0,
	.passdb_need = MECH_PASSDB_NEED_VERIFY_PLAIN,

	mech_external_auth_new,
	mech_generic_auth_initial,
	mech_external_auth_continue,
	mech_generic_auth_free
};
