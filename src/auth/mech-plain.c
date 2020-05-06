/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "safe-memset.h"
#include "mech.h"
#include "passdb.h"
#include "mech-plain-common.h"

static void
mech_plain_auth_continue(struct auth_request *request,
			 const unsigned char *data, size_t data_size)
{
	const char *authid, *authenid, *error;
	char *pass;
	size_t i, len;
	int count;

	/* authorization ID \0 authentication ID \0 pass. */
	authid = (const char *) data;
	authenid = NULL; pass = NULL;

	count = 0;
	for (i = 0; i < data_size; i++) {
		if (data[i] == '\0') {
			if (++count == 1)
				authenid = (const char *) data + i+1;
			else if (count == 2) {
				i++;
				len = data_size - i;
				pass = p_strndup(unsafe_data_stack_pool,
						 data+i, len);
			}
			else
				break;
		}
	}

	if (authenid != NULL && strcmp(authid, authenid) == 0) {
		/* the login username isn't different */
		authid = "";
	}

	if (count != 2) {
		/* invalid input */
		e_info(request->mech_event, "invalid input");
		auth_request_fail(request);
	} else if (!auth_request_set_username(request, authenid, &error)) {
                /* invalid username */
                e_info(request->mech_event, "%s", error);
                auth_request_fail(request);
        } else if (*authid != '\0' &&
                   !auth_request_set_login_username(request, authid, &error)) {
                /* invalid login username */
                e_info(request->mech_event,
		       "login user: %s", error);
                auth_request_fail(request);
        } else {
                auth_request_verify_plain(request, pass,
                                          plain_verify_callback);
	}

        /* make sure it's cleared */
	if (pass != NULL)
		safe_memset(pass, 0, strlen(pass));
}

static struct auth_request *mech_plain_auth_new(void)
{
        struct auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"plain_auth_request", 2048);
	request = p_new(pool, struct auth_request, 1);
	request->pool = pool;
	return request;
}

const struct mech_module mech_plain = {
	"PLAIN",

	.flags = MECH_SEC_PLAINTEXT | MECH_SEC_ALLOW_NULS,
	.passdb_need = MECH_PASSDB_NEED_VERIFY_PLAIN,

	mech_plain_auth_new,
	mech_generic_auth_initial,
	mech_plain_auth_continue,
	mech_generic_auth_free
};
