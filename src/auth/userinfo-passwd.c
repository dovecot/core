/*
   Loosely based on auth_passwd.c from popa3d by
   Solar Designer <solar@openwall.com>

   Copyright (C) 2002 Timo Sirainen
*/

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERINFO_PASSWD

#include "userinfo-passwd.h"
#include "mycrypt.h"

void passwd_fill_cookie_reply(struct passwd *pw, AuthCookieReplyData *reply)
{
	i_assert(sizeof(reply->system_user) > strlen(pw->pw_name));
	i_assert(sizeof(reply->virtual_user) > strlen(pw->pw_name));
	i_assert(sizeof(reply->home) > strlen(pw->pw_dir));

	reply->uid = pw->pw_uid;
	reply->gid = pw->pw_gid;

	strcpy(reply->system_user, pw->pw_name);
	strcpy(reply->virtual_user, pw->pw_name);
	strcpy(reply->home, pw->pw_dir);
}

static int passwd_verify_plain(const char *user, const char *password,
			       AuthCookieReplyData *reply)
{
	struct passwd *pw;
	int result;

	pw = getpwnam(user);
	if (pw == NULL || !IS_VALID_PASSWD(pw->pw_passwd))
		return FALSE;

	/* check if the password is valid */
	result = strcmp(mycrypt(password, pw->pw_passwd), pw->pw_passwd) == 0;

	/* clear the passwords from memory */
	safe_memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));

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
