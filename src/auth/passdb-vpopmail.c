/* Copyright (C) 2002-2003 Timo Sirainen */

/* Thanks to Courier-IMAP for showing how the vpopmail API should be used */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_VPOPMAIL

#include "common.h"
#include "safe-memset.h"
#include "passdb.h"
#include "mycrypt.h"

#include "userdb-vpopmail.h"

static void
vpopmail_verify_plain(struct auth_request *request, const char *password,
		      verify_plain_callback_t *callback)
{
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
	int result;

	vpw = vpopmail_lookup_vqp(request->user,
				  vpop_user, vpop_domain);
	if (vpw == NULL) {
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (((vpw->pw_gid & NO_IMAP) != 0 &&
	     strcmp(request->protocol, "IMAP") == 0) ||
	    ((vpw->pw_gid & NO_POP) != 0 &&
	     strcmp(request->protocol, "POP3") == 0)) {
		if (verbose) {
			i_info("vpopmail(%s): %s disabled",
			       get_log_prefix(request), request->protocol);
		}
		callback(PASSDB_RESULT_USER_DISABLED, request);
		return;
	}

	/* verify password */
	result = strcmp(mycrypt(password, vpw->pw_passwd), vpw->pw_passwd) == 0;
	safe_memset(vpw->pw_passwd, 0, strlen(vpw->pw_passwd));

	if (!result) {
		if (verbose) {
			i_info("vpopmail(%s): password mismatch",
			       get_log_prefix(request));
		}

		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	callback(PASSDB_RESULT_OK, request);
}

static void vpopmail_deinit(void)
{
	vclose();
}

struct passdb_module passdb_vpopmail = {
	NULL,
	vpopmail_deinit,

	vpopmail_verify_plain,
	NULL
};

#endif
