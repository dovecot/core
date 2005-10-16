/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"

#ifdef PASSDB_BSDAUTH

#include "safe-memset.h"
#include "passdb.h"
#include "mycrypt.h"

#include <login_cap.h>
#include <bsd_auth.h>
#include <pwd.h>

extern struct passdb_module passdb_bsdauth;
static char *bsdauth_cache_key;

static void
bsdauth_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct passwd *pw;
	int result;

	pw = getpwnam(request->user);
	if (pw == NULL) {
		auth_request_log_info(request, "bsdauth", "unknown user");
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (!IS_VALID_PASSWD(pw->pw_passwd)) {
		auth_request_log_info(request, "bsdauth",
				      "invalid password field");
		callback(PASSDB_RESULT_USER_DISABLED, request);
		return;
	}

	/* check if the password is valid */
	result = auth_userokay(request->user, NULL, NULL,
			       t_strdup_noconst(password));

	/* clear the passwords from memory */
	safe_memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));

	if (!result) {
		auth_request_log_info(request, "bsdauth", "password mismatch");
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	/* make sure we're using the username exactly as it's in the database */
        auth_request_set_field(request, "user", pw->pw_name, NULL);

	callback(PASSDB_RESULT_OK, request);
}

static void bsdauth_init(const char *args)
{
	bsdauth_cache_key = NULL;

	if (strncmp(args, "cache_key=", 10) == 0)
		bsdauth_cache_key = i_strdup(args + 10);

	passdb_bsdauth.cache_key = bsdauth_cache_key;
}

static void bsdauth_deinit(void)
{
	endpwent();
	i_free(bsdauth_cache_key);
}

struct passdb_module passdb_bsdauth = {
	"bsdauth",
	NULL, NULL, FALSE,

	NULL,
	bsdauth_init,
	bsdauth_deinit,

	bsdauth_verify_plain,
	NULL
};

#endif
