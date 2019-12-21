/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_BSDAUTH

#include "safe-memset.h"
#include "auth-cache.h"
#include "ipwd.h"
#include "mycrypt.h"

#include <login_cap.h>
#include <bsd_auth.h>

static void
bsdauth_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	const char *type;
	auth_session_t *result;

	e_debug(authdb_event(request), "lookup");

	/* check if the auth is valid */
	type = t_strdup_printf("auth-%s", request->service);
	result = auth_usercheck(request->user, NULL, t_strdup_noconst(type),
			       t_strdup_noconst(password));

	if (auth_getstate(result) == 0) {
		auth_request_log_password_mismatch(request, AUTH_SUBSYS_DB);
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	/* make sure we're using the username as defined by the database.
	 * On OpenBSD, auth "styles" will translate a request->user of "name:style"
	 * to "name" authenticated via "style"; or the default auth style on a system
	 * might do something unusual to map any input to any username it wants.
	 * See authenticate(3).
	 */
	if(auth_getpwd(result) == NULL) {
		/* FIXME: internal error?
		 * It would be strange but not impossible to
		 * accept a user with missing account details.
		 */
		auth_request_set_field(request, "user", NULL, NULL);
	} else {
		auth_request_set_field(request, "user", auth_getpwd(result)->pw_name, NULL);
	}

	auth_close(result); // should equal the earlier auth_getstate()

	callback(PASSDB_RESULT_OK, request);
}

static struct passdb_module *
bsdauth_preinit(pool_t pool, const char *args)
{
	struct passdb_module *module;

	module = p_new(pool, struct passdb_module, 1);
	module->default_pass_scheme = "PLAIN"; /* same reason as PAM */
	module->blocking = TRUE;

	if (strcmp(args, "blocking=no") == 0)
		module->blocking = FALSE;
	else if (str_begins(args, "cache_key="))
		module->default_cache_key = auth_cache_parse_key(pool, args + 10);
	else if (*args != '\0')
		i_fatal("passdb bsdauth: Unknown setting: %s", args);
	return module;
}

static void bsdauth_deinit(struct passdb_module *module ATTR_UNUSED)
{
	endpwent();
}

struct passdb_module_interface passdb_bsdauth = {
	"bsdauth",

	bsdauth_preinit,
	NULL,
	bsdauth_deinit,

	bsdauth_verify_plain,
	NULL,
	NULL
};
#else
struct passdb_module_interface passdb_bsdauth = {
	.name = "bsdauth"
};
#endif
