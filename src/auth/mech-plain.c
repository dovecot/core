/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "safe-memset.h"
#include "mech.h"
#include "passdb.h"

static void verify_callback(enum passdb_result result,
			    struct auth_request *request)
{
	switch (result) {
	case PASSDB_RESULT_OK:
		mech_auth_success(request, NULL, 0);
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		mech_auth_internal_failure(request);
		break;
	default:
		mech_auth_fail(request);
		break;
	}
}

static void
mech_plain_auth_continue(struct auth_request *request,
			 const unsigned char *data, size_t data_size,
			 mech_callback_t *callback)
{
	const char *authid, *authenid, *error;
	char *pass;
	size_t i, count, len;

	request->callback = callback;

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
			       get_log_prefix(request));
		}
		mech_auth_fail(request);
	} else {
		/* split and save user/realm */
		if (strchr(authenid, '@') == NULL && default_realm != NULL) {
			request->user = p_strconcat(request->pool,
						    authenid, "@",
						    default_realm, NULL);
		} else {
			request->user = p_strdup(request->pool, authenid);
		}

		if (!mech_fix_username(request->user, &error)) {
			/* invalid username */
			if (verbose) {
				i_info("plain(%s): %s",
				       get_log_prefix(request), error);
			}
			mech_auth_fail(request);
		} else {
			passdb->verify_plain(request, pass, verify_callback);
		}

		/* make sure it's cleared */
		safe_memset(pass, 0, strlen(pass));
	}
}

static void
mech_plain_auth_initial(struct auth_request *request,
			const unsigned char *data, size_t data_size,
			mech_callback_t *callback)
{
	if (data_size == 0)
		callback(request, AUTH_CLIENT_RESULT_CONTINUE, NULL, 0);
	else
		mech_plain_auth_continue(request, data, data_size, callback);
}

static void
mech_plain_auth_free(struct auth_request *request)
{
	pool_unref(request->pool);
}

static struct auth_request *mech_plain_auth_new(void)
{
        struct auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create("plain_auth_request", 256);
	request = p_new(pool, struct auth_request, 1);
	request->refcount = 1;
	request->pool = pool;
	return request;
}

struct mech_module mech_plain = {
	"PLAIN",

	MEMBER(flags) MECH_SEC_PLAINTEXT,

	MEMBER(passdb_need_plain) TRUE,
	MEMBER(passdb_need_credentials) FALSE,

	mech_plain_auth_new,
	mech_plain_auth_initial,
	mech_plain_auth_continue,
        mech_plain_auth_free
};
