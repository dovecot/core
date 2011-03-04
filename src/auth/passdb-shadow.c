/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_SHADOW

#include "safe-memset.h"

#include <shadow.h>

#define SHADOW_CACHE_KEY "%u"
#define SHADOW_PASS_SCHEME "CRYPT"

static void
shadow_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct spwd *spw;
	int ret;

	auth_request_log_debug(request, "shadow", "lookup");

	spw = getspnam(request->user);
	if (spw == NULL) {
		auth_request_log_info(request, "shadow", "unknown user");
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (!IS_VALID_PASSWD(spw->sp_pwdp)) {
		auth_request_log_info(request, "shadow",
				      "invalid password field");
		callback(PASSDB_RESULT_USER_DISABLED, request);
		return;
	}

	/* save the password so cache can use it */
	auth_request_set_field(request, "password", spw->sp_pwdp,
			       SHADOW_PASS_SCHEME);

	/* check if the password is valid */
	ret = auth_request_password_verify(request, password, spw->sp_pwdp,
					   SHADOW_PASS_SCHEME, "shadow");

	/* clear the passwords from memory */
	safe_memset(spw->sp_pwdp, 0, strlen(spw->sp_pwdp));

	if (ret <= 0) {
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	/* make sure we're using the username exactly as it's in the database */
        auth_request_set_field(request, "user", spw->sp_namp, NULL);

	callback(PASSDB_RESULT_OK, request);
}

static void shadow_init(struct passdb_module *module)
{
	module->blocking = TRUE;
	if (strcmp(module->args, "blocking=no") == 0)
		module->blocking = FALSE;
	else if (*module->args != '\0')
		i_fatal("passdb shadow: Unknown setting: %s", module->args);

	module->cache_key = SHADOW_CACHE_KEY;
	module->default_pass_scheme = SHADOW_PASS_SCHEME;
}

static void shadow_deinit(struct passdb_module *module ATTR_UNUSED)
{
        endspent();
}

struct passdb_module_interface passdb_shadow = {
	"shadow",

	NULL,
	shadow_init,
	shadow_deinit,

	shadow_verify_plain,
	NULL,
	NULL
};
#else
struct passdb_module_interface passdb_shadow = {
	.name = "shadow"
};
#endif
