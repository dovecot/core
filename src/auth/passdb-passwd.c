/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_PASSWD

#include "common.h"
#include "safe-memset.h"
#include "passdb.h"
#include "mycrypt.h"

#include <pwd.h>

static void
passwd_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct passwd *pw;
	int result;

	pw = getpwnam(request->user);
	if (pw == NULL) {
		auth_request_log_info(request, "passwd", "unknown user");
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (!IS_VALID_PASSWD(pw->pw_passwd)) {
		auth_request_log_info(request, "passwd",
			"invalid password field '%s'", pw->pw_passwd);
		callback(PASSDB_RESULT_USER_DISABLED, request);
		return;
	}

	/* check if the password is valid */
	result = strcmp(mycrypt(password, pw->pw_passwd), pw->pw_passwd) == 0;

	/* clear the passwords from memory */
	safe_memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));

	if (!result) {
		auth_request_log_info(request, "passwd", "password mismatch");
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	callback(PASSDB_RESULT_OK, request);
}

static void passwd_deinit(void)
{
	endpwent();
}

struct passdb_module passdb_passwd = {
	"passwd",
	"%u", "CRYPT",

	NULL, NULL,
	passwd_deinit,

	passwd_verify_plain,
	NULL
};

#endif
