/*
   Loosely based on auth_shadow.c from popa3d by
   Solar Designer <solar@openwall.com>

   Copyright (C) 2002 Timo Sirainen
*/

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERINFO_SHADOW

#include "userinfo-passwd.h"

#include <shadow.h>

static int shadow_verify_plain(const char *user, const char *password,
			       AuthCookieReplyData *reply)
{
	struct passwd *pw;
	struct spwd *spw;
	char *passdup;
	int result;

	spw = getspnam(user);
	if (spw == NULL || !IS_VALID_PASSWD(spw->sp_pwdp))
		return FALSE;

	/* check if the password is valid */
        passdup = t_strdup_noconst(password);
	result = strcmp(crypt(passdup, spw->sp_pwdp), spw->sp_pwdp) == 0;

	/* clear the passwords from memory */
	memset(passdup, 0, strlen(passdup));
	memset(spw->sp_pwdp, 0, strlen(spw->sp_pwdp));

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

UserInfoModule userinfo_shadow = {
	NULL,
	shadow_deinit,

	shadow_verify_plain,
	NULL
};

#endif
