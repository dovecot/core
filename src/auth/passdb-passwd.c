/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_PASSWD

#include "common.h"
#include "safe-memset.h"
#include "passdb.h"
#include "mycrypt.h"

#include <pwd.h>

static enum passdb_result
passwd_verify_plain(const char *user, const char *realm, const char *password)
{
	struct passwd *pw;
	int result;

	if (realm != NULL)
		user = t_strconcat(user, "@", realm, NULL);
	pw = getpwnam(user);
	if (pw == NULL) {
		if (errno != 0)
			i_error("getpwnam(%s) failed: %m", user);
		else if (verbose)
			i_info("passwd(%s): unknown user", user);
		return PASSDB_RESULT_USER_UNKNOWN;
	}

	if (!IS_VALID_PASSWD(pw->pw_passwd)) {
		if (verbose) {
			i_info("passwd(%s): invalid password field '%s'",
			       user, pw->pw_passwd);
		}
		return PASSDB_RESULT_USER_DISABLED;
	}

	/* check if the password is valid */
	result = strcmp(mycrypt(password, pw->pw_passwd), pw->pw_passwd) == 0;

	/* clear the passwords from memory */
	safe_memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));

	if (!result) {
		if (verbose)
			i_info("passwd(%s): password mismatch", user);
		return PASSDB_RESULT_PASSWORD_MISMATCH;
	}

	return PASSDB_RESULT_OK;
}

static void passwd_deinit(void)
{
	endpwent();
}

struct passdb_module passdb_passwd = {
	NULL,
	passwd_deinit,

	passwd_verify_plain,
	NULL
};

#endif
