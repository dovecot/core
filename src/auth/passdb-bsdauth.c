/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_BSDAUTH

#include "common.h"
#include "safe-memset.h"
#include "passdb.h"
#include "mycrypt.h"

#include <login_cap.h>
#include <bsd_auth.h>
#include <pwd.h>

static void
bsdauth_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct passwd *pw;
	int result;

	pw = getpwnam(request->user);
	if (pw == NULL) {
		if (verbose)
			i_info("passwd(%s): unknown user", request->user);
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (!IS_VALID_PASSWD(pw->pw_passwd)) {
		if (verbose) {
			i_info("passwd(%s): invalid password field '%s'",
			       request->user, pw->pw_passwd);
		}
		callback(PASSDB_RESULT_USER_DISABLED, request);
		return;
	}

	/* check if the password is valid */
	result = auth_userokay(request->user, NULL, NULL, password);

	/* clear the passwords from memory */
	safe_memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));

	if (!result) {
		if (verbose)
			i_info("passwd(%s): password mismatch", request->user);
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	callback(PASSDB_RESULT_OK, request);
}

static void bsdauth_deinit(void)
{
	endpwent();
}

struct passdb_module passdb_bsdauth = {
	NULL,
	bsdauth_deinit,

	bsdauth_verify_plain,
	NULL
};

#endif
