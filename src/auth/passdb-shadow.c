/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_PASSWD

#include "common.h"
#include "safe-memset.h"
#include "passdb.h"
#include "mycrypt.h"

#include <shadow.h>

static void
shadow_verify_plain(const char *user, const char *realm, const char *password,
		    verify_plain_callback_t *callback, void *context)
{
	struct spwd *spw;
	int result;

	if (realm != NULL)
		user = t_strconcat(user, "@", realm, NULL);
	spw = getspnam(user);
	if (spw == NULL) {
		if (errno != 0)
			i_error("getspnam(%s) failed: %m", user);
		else if (verbose)
			i_info("shadow(%s): unknown user", user);
		callback(PASSDB_RESULT_USER_UNKNOWN, context);
		return;
	}

	if (!IS_VALID_PASSWD(spw->sp_pwdp)) {
		if (verbose) {
			i_info("shadow(%s): invalid password field '%s'",
			       user, spw->sp_pwdp);
		}
		callback(PASSDB_RESULT_USER_DISABLED, context);
		return;
	}

	/* check if the password is valid */
	result = strcmp(mycrypt(password, spw->sp_pwdp), spw->sp_pwdp) == 0;

	/* clear the passwords from memory */
	safe_memset(spw->sp_pwdp, 0, strlen(spw->sp_pwdp));

	if (!result) {
		if (verbose)
			i_info("shadow(%s): password mismatch", user);
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, context);
		return;
	}

	callback(PASSDB_RESULT_OK, context);
}

static void shadow_deinit(void)
{
        endspent();
}

struct passdb_module passdb_shadow = {
	NULL,
	shadow_deinit,

	shadow_verify_plain,
	NULL
};

#endif
