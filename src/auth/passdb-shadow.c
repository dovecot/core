/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_SHADOW

#include "safe-memset.h"

#include <shadow.h>

#define SHADOW_CACHE_KEY "%u"
#define SHADOW_PASS_SCHEME "CRYPT"

static enum passdb_result
shadow_lookup(struct auth_request *request, struct spwd **spw_r)
{
	e_debug(authdb_event(request), "lookup");

	*spw_r = getspnam(request->user);
	if (*spw_r == NULL) {
		auth_request_log_unknown_user(request, AUTH_SUBSYS_DB);
		return PASSDB_RESULT_USER_UNKNOWN;
	}

	if (!IS_VALID_PASSWD((*spw_r)->sp_pwdp)) {
		e_info(authdb_event(request),
		       "invalid password field");
		return PASSDB_RESULT_USER_DISABLED;
	}

	/* save the password so cache can use it */
	auth_request_set_field(request, "password", (*spw_r)->sp_pwdp,
			       SHADOW_PASS_SCHEME);
	return PASSDB_RESULT_OK;
}

static void
shadow_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct spwd *spw;
	enum passdb_result res;
	int ret;

	res = shadow_lookup(request, &spw);
	if (res != PASSDB_RESULT_OK) {
		callback(res, request);
		return;
	}

	/* check if the password is valid */
	ret = auth_request_password_verify(request, password, spw->sp_pwdp,
					   SHADOW_PASS_SCHEME, AUTH_SUBSYS_DB);

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

static void
shadow_lookup_credentials(struct auth_request *request,
			  lookup_credentials_callback_t *callback)
{
	struct spwd *spw;
	enum passdb_result res;

	res = shadow_lookup(request, &spw);
	if (res != PASSDB_RESULT_OK) {
		callback(res, NULL, 0, request);
		return;
	}
	/* make sure we're using the username exactly as it's in the database */
        auth_request_set_field(request, "user", spw->sp_namp, NULL);
	passdb_handle_credentials(PASSDB_RESULT_OK, spw->sp_pwdp,
				  SHADOW_PASS_SCHEME, callback, request);
}

static struct passdb_module *
shadow_preinit(pool_t pool, const char *args)
{
	struct passdb_module *module;

	module = p_new(pool, struct passdb_module, 1);
	module->blocking = TRUE;
	if (strcmp(args, "blocking=no") == 0)
		module->blocking = FALSE;
	else if (*args != '\0')
		i_fatal("passdb shadow: Unknown setting: %s", args);

	module->default_cache_key = SHADOW_CACHE_KEY;
	module->default_pass_scheme = SHADOW_PASS_SCHEME;
	return module;
}

static void shadow_deinit(struct passdb_module *module ATTR_UNUSED)
{
        endspent();
}

struct passdb_module_interface passdb_shadow = {
	"shadow",

	shadow_preinit,
	NULL,
	shadow_deinit,

	shadow_verify_plain,
	shadow_lookup_credentials,
	NULL
};
#else
struct passdb_module_interface passdb_shadow = {
	.name = "shadow"
};
#endif
