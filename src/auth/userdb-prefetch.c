/* Copyright (c) 2004-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "userdb.h"

#ifdef USERDB_PREFETCH

#include "str.h"
#include "var-expand.h"

#include <stdlib.h>

static void prefetch_lookup(struct auth_request *auth_request,
			    userdb_callback_t *callback)
{
	/* auth_request_set_field() should have already placed the userdb_*
	   values to userdb_reply. */
	if (auth_request->userdb_reply == NULL) {
		if (auth_request->auth->userdbs->next == NULL) {
			/* no other userdbs */
			auth_request_log_error(auth_request, "prefetch",
				"passdb didn't return userdb entries");
		} else if (!auth_request->userdb_lookup ||
			   auth_request->auth->verbose_debug) {
			/* more userdbs, they may know the user */
			auth_request_log_info(auth_request, "prefetch",
				"passdb didn't return userdb entries, "
				"trying the next userdb");
		}
		callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
		return;
	}

	auth_request_log_debug(auth_request, "prefetch", "success");
	callback(USERDB_RESULT_OK, auth_request);
}

struct userdb_module_interface userdb_prefetch = {
	"prefetch",

	NULL,
	NULL,
	NULL,

	prefetch_lookup
};
#else
struct userdb_module_interface userdb_prefetch = {
	MEMBER(name) "prefetch"
};
#endif
