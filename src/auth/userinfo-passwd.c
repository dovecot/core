/*
   Loosely based on auth_passwd.c from popa3d by
   Solar Designer <solar@openwall.com>

   Copyright (C) 2002 Timo Sirainen
*/

#define _XOPEN_SOURCE 4
#define _XOPEN_SOURCE_EXTENDED
#define _XPG4_2

#include "common.h"

#ifdef USERINFO_PASSWD

#include "userinfo.h"
#include "userinfo-passwd.h"

#include <unistd.h>

void passwd_fill_cookie_reply(struct passwd *pw, AuthCookieReplyData *reply)
{
	i_assert(sizeof(reply->user) > strlen(pw->pw_name));
	i_assert(sizeof(reply->home) > strlen(pw->pw_dir));

	reply->uid = pw->pw_uid;
	reply->gid = pw->pw_gid;

	strcpy(reply->user, pw->pw_name);
	strcpy(reply->home, pw->pw_dir);
}

static int passwd_verify_plain(const char *user, const char *password,
			       AuthCookieReplyData *reply)
{
	struct passwd *pw;
	char *passdup;
	int result;

	pw = getpwnam(user);
	if (pw == NULL || !IS_VALID_PASSWD(pw->pw_passwd))
		return FALSE;

	/* check if the password is valid */
        passdup = t_strdup_noconst(password);
	result = strcmp(crypt(passdup, pw->pw_passwd), pw->pw_passwd) == 0;

	/* clear the passwords from memory */
	memset(passdup, 0, strlen(passdup));
	memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));

	if (!result)
		return FALSE;

	/* password ok, save the user info */
        passwd_fill_cookie_reply(pw, reply);
	return TRUE;
}

static void passwd_deinit(void)
{
	endpwent();
}

UserInfoModule userinfo_passwd = {
	NULL,
	passwd_deinit,

	passwd_verify_plain,
	NULL
};

#endif
