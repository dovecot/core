/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_PASSWD

#include "safe-memset.h"
#include "ipwd.h"

#define PASSWD_CACHE_KEY "%u"
#define PASSWD_PASS_SCHEME "CRYPT"

static enum passdb_result
passwd_lookup(struct auth_request *request, struct passwd *pw_r)
{
	e_debug(authdb_event(request), "lookup");

	switch (i_getpwnam(request->user, pw_r)) {
	case -1:
		e_error(authdb_event(request),
			"getpwnam() failed: %m");
		return PASSDB_RESULT_INTERNAL_FAILURE;
	case 0:
		auth_request_log_unknown_user(request, AUTH_SUBSYS_DB);
		return PASSDB_RESULT_USER_UNKNOWN;
	}

	if (!IS_VALID_PASSWD(pw_r->pw_passwd)) {
		e_info(authdb_event(request),
		       "invalid password field '%s'", pw_r->pw_passwd);
		return PASSDB_RESULT_USER_DISABLED;
	}

	/* save the password so cache can use it */
	auth_request_set_field(request, "password", pw_r->pw_passwd,
			       PASSWD_PASS_SCHEME);
	return PASSDB_RESULT_OK;
}

static void
passwd_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct passwd pw;
	enum passdb_result res;
	int ret;

	res = passwd_lookup(request, &pw);
	if (res != PASSDB_RESULT_OK) {
		callback(res, request);
		return;
	}
	/* check if the password is valid */
	ret = auth_request_password_verify(request, password, pw.pw_passwd,
					   PASSWD_PASS_SCHEME, AUTH_SUBSYS_DB);

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

static void
passwd_lookup_credentials(struct auth_request *request,
			  lookup_credentials_callback_t *callback)
{
	struct passwd pw;
	enum passdb_result res;

	res = passwd_lookup(request, &pw);
	if (res != PASSDB_RESULT_OK) {
		callback(res, NULL, 0, request);
		return;
	}
	/* make sure we're using the username exactly as it's in the database */
        auth_request_set_field(request, "user", pw.pw_name, NULL);
	passdb_handle_credentials(PASSDB_RESULT_OK, pw.pw_passwd,
				  PASSWD_PASS_SCHEME, callback, request);
}

static struct passdb_module *
passwd_preinit(pool_t pool, const char *args)
{
	struct passdb_module *module;

	module = p_new(pool, struct passdb_module, 1);
	module->blocking = TRUE;
	if (strcmp(args, "blocking=no") == 0)
		module->blocking = FALSE;
	else if (*args != '\0')
		i_fatal("passdb passwd: Unknown setting: %s", args);

	module->default_cache_key = PASSWD_CACHE_KEY;
	module->default_pass_scheme = PASSWD_PASS_SCHEME;
	return module;
}

static void passwd_deinit(struct passdb_module *module ATTR_UNUSED)
{
	endpwent();
}

struct passdb_module_interface passdb_passwd = {
	"passwd",

	passwd_preinit,
	NULL,
	passwd_deinit,

	passwd_verify_plain,
	passwd_lookup_credentials,
	NULL
};

#else
struct passdb_module_interface passdb_passwd = {
	.name = "passwd"
};
#endif
