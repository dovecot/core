/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_SHADOW

#include "common.h"
#include "safe-memset.h"
#include "passdb.h"
#include "mycrypt.h"

#include <shadow.h>

static void
shadow_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct spwd *spw;
	int result;

	spw = getspnam(request->user);
	if (spw == NULL) {
		if (verbose) {
			i_info("shadow(%s): unknown user",
			       get_log_prefix(request));
		}
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (!IS_VALID_PASSWD(spw->sp_pwdp)) {
		if (verbose) {
			i_info("shadow(%s): invalid password field '%s'",
			       get_log_prefix(request), spw->sp_pwdp);
		}
		callback(PASSDB_RESULT_USER_DISABLED, request);
		return;
	}

	/* check if the password is valid */
	result = strcmp(mycrypt(password, spw->sp_pwdp), spw->sp_pwdp) == 0;

	/* clear the passwords from memory */
	safe_memset(spw->sp_pwdp, 0, strlen(spw->sp_pwdp));

	if (!result) {
		if (verbose) {
			i_info("shadow(%s): password mismatch",
			       get_log_prefix(request));
		}
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	callback(PASSDB_RESULT_OK, request);
}

static void shadow_deinit(void)
{
        endspent();
}

struct passdb_module passdb_shadow = {
	"shadow",

	NULL, NULL,
	shadow_deinit,

	shadow_verify_plain,
	NULL
};

#endif
