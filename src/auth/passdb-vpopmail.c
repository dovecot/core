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
vpopmail_verify_plain(const char *user, const char *realm, const char *password,
		      verify_plain_callback_t *callback, void *context)
{
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
	int result;

	vpw = vpopmail_lookup_vqp(user, realm, vpop_user, vpop_domain);
	if (vpw == NULL) {
		callback(PASSDB_RESULT_USER_UNKNOWN, context);
		return;
	}

	if ((vpw->pw_gid & NO_IMAP) != 0) {
		if (verbose)
			i_info("vpopmail(%s): IMAP disabled", user);
		callback(PASSDB_RESULT_USER_DISABLED, context);
		return;
	}

	/* verify password */
	result = strcmp(mycrypt(password, vpw->pw_passwd), vpw->pw_passwd) == 0;
	safe_memset(vpw->pw_passwd, 0, strlen(vpw->pw_passwd));

	if (!result) {
		if (verbose)
			i_info("vpopmail(%s): password mismatch", user);
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, context);
		return;
	}

	callback(PASSDB_RESULT_OK, context);
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
