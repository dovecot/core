/*
   Loosely based on auth_shadow.c from popa3d by
   Solar Designer <solar@openwall.com>

   Copyright (C) 2002 Timo Sirainen
*/

#ifndef _XOPEN_SOURCE_EXTENDED
#  define _XOPEN_SOURCE_EXTENDED
#endif
#define _XOPEN_SOURCE 4
#define _XPG4_2

#include "common.h"

#ifdef USERINFO_SHADOW

#include "userinfo.h"
#include "userinfo-passwd.h"

#include <unistd.h>
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
