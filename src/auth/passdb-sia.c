/* Copyright (C) 2006 Simon L Jackson */

/* Tru64 SIA support */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_SIA

#include "safe-memset.h"

#include <sia.h>
#include <siad.h>
#include <sys/security.h>

static int checkpw_collect(int timeout ATTR_UNUSED, int rendition,
			   uchar_t *title ATTR_UNUSED,
			   int nprompts ATTR_UNUSED,
			   prompt_t *prompts ATTR_UNUSED)
{
	switch (rendition) {
	case SIAONELINER:
	case SIAINFO:
	case SIAWARNING:
		return SIACOLSUCCESS;
	}

	/* everything else is bogus */
	return SIACOLABORT;
}

static void
local_sia_verify_plain(struct auth_request *request, const char *password,
		       verify_plain_callback_t *callback)
{
	char *argutility = "dovecot";

	auth_request_log_debug(request, "sia", "lookup");

	/* check if the password is valid */
	if (sia_validate_user(checkpw_collect, 1, &argutility, NULL,
			      (char *)request->user, NULL, NULL, NULL,
			      (char *)password) != SIASUCCESS) {
		auth_request_log_password_mismatch(request, "sia");
                callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
	} else {
		callback(PASSDB_RESULT_OK, request);
	}
}

struct passdb_module_interface passdb_sia = {
        "sia",

        NULL,
        NULL,
        NULL,

        local_sia_verify_plain,
	NULL,
	NULL
};
#else
struct passdb_module_interface passdb_sia = {
	.name = "sia"
};
#endif
