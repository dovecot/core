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

static enum passdb_result
vpopmail_verify_plain(const char *user, const char *realm, const char *password)
{
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
	int result;

	vpw = vpopmail_lookup_vqp(user, realm, vpop_user, vpop_domain);
	if (vpw == NULL)
		return PASSDB_RESULT_USER_UNKNOWN;

	if ((vpw->pw_gid & NO_IMAP) != 0) {
		if (verbose)
			i_info("vpopmail(%s): IMAP disabled", user);
		return PASSDB_RESULT_USER_DISABLED;
	}

	/* verify password */
	result = strcmp(mycrypt(password, vpw->pw_passwd), vpw->pw_passwd) == 0;
	safe_memset(vpw->pw_passwd, 0, strlen(vpw->pw_passwd));

	if (!result) {
		if (verbose)
			i_info("vpopmail(%s): password mismatch", user);
		return PASSDB_RESULT_PASSWORD_MISMATCH;
	}

	return PASSDB_RESULT_OK;
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
