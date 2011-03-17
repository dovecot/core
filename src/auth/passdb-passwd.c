/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_PASSWD

#include "safe-memset.h"
#include "ipwd.h"

#define PASSWD_CACHE_KEY "%u"
#define PASSWD_PASS_SCHEME "CRYPT"

static void
passwd_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct passwd pw;
	int ret;

	auth_request_log_debug(request, "passwd", "lookup");

	switch (i_getpwnam(request->user, &pw)) {
	case -1:
		auth_request_log_error(request, "passwd",
				       "getpwnam() failed: %m");
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	case 0:
		auth_request_log_info(request, "passwd", "unknown user");
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (!IS_VALID_PASSWD(pw.pw_passwd)) {
		auth_request_log_info(request, "passwd",
			"invalid password field '%s'", pw.pw_passwd);
		callback(PASSDB_RESULT_USER_DISABLED, request);
		return;
	}

	/* save the password so cache can use it */
	auth_request_set_field(request, "password", pw.pw_passwd,
			       PASSWD_PASS_SCHEME);

	/* check if the password is valid */
	ret = auth_request_password_verify(request, password, pw.pw_passwd,
					   PASSWD_PASS_SCHEME, "passwd");

	/* clear the passwords from memory */
	safe_memset(pw.pw_passwd, 0, strlen(pw.pw_passwd));

	if (ret <= 0) {
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	/* make sure we're using the username exactly as it's in the database */
        auth_request_set_field(request, "user", pw.pw_name, NULL);

	callback(PASSDB_RESULT_OK, request);
}

static void passwd_init(struct passdb_module *module)
{
	module->blocking = TRUE;
	if (strcmp(module->args, "blocking=no") == 0)
		module->blocking = FALSE;
	else if (*module->args != '\0')
		i_fatal("passdb passwd: Unknown setting: %s", module->args);

	module->cache_key = PASSWD_CACHE_KEY;
	module->default_pass_scheme = PASSWD_PASS_SCHEME;
}

static void passwd_deinit(struct passdb_module *module ATTR_UNUSED)
{
	endpwent();
}

struct passdb_module_interface passdb_passwd = {
	"passwd",

	NULL,
	passwd_init,
	passwd_deinit,

	passwd_verify_plain,
	NULL,
	NULL
};

#else
struct passdb_module_interface passdb_passwd = {
	.name = "passwd"
};
#endif
