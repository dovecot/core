/*
   Loosely based on auth_shadow.c from popa3d by
   Solar Designer <solar@openwall.com>

   Copyright (C) 2002 Timo Sirainen
*/

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERINFO_SHADOW

#include "userinfo-passwd.h"
#include "mycrypt.h"

#include <shadow.h>

static int shadow_verify_plain(const char *user, const char *password,
			       struct auth_cookie_reply_data *reply)
{
	struct passwd *pw;
	struct spwd *spw;
	int result;

	spw = getspnam(user);
	if (spw == NULL || !IS_VALID_PASSWD(spw->sp_pwdp))
		return FALSE;

	/* check if the password is valid */
	result = strcmp(mycrypt(password, spw->sp_pwdp), spw->sp_pwdp) == 0;

	/* clear the passwords from memory */
	safe_memset(spw->sp_pwdp, 0, strlen(spw->sp_pwdp));

	if (!result)
		return FALSE;

	/* password ok, save the user info */
	pw = getpwnam(user);
	if (pw == NULL)
		return FALSE;

        passwd_fill_cookie_reply(pw, reply);
	return TRUE;
}

static void shadow_deinit(void)
{
	endpwent();
        endspent();
}

struct user_info_module userinfo_shadow = {
	NULL,
	shadow_deinit,

	shadow_verify_plain,
	NULL
};

#endif
