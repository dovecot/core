/*
   Loosely based on auth_passwd.c from popa3d by
   Solar Designer <solar@openwall.com>

   Copyright (C) 2002 Timo Sirainen
*/

#include "config.h"
#undef HAVE_CONFIG_H

#include "userinfo-passwd.h"

void passwd_fill_cookie_reply(struct passwd *pw,
			      struct auth_cookie_reply_data *reply)
{
	reply->uid = pw->pw_uid;
	reply->gid = pw->pw_gid;

	if (strocpy(reply->system_user, pw->pw_name,
		    sizeof(reply->system_user)) < 0)
		i_panic("system_user overflow");
	if (strocpy(reply->virtual_user, pw->pw_name,
		    sizeof(reply->virtual_user)) < 0)
		i_panic("virtual_user overflow");
	if (strocpy(reply->home, pw->pw_dir, sizeof(reply->home)) < 0)
		i_panic("home overflow");
}

#ifdef USERINFO_PASSWD

#include "mycrypt.h"

static int passwd_verify_plain(const char *user, const char *password,
			       struct auth_cookie_reply_data *reply)
{
	struct passwd *pw;
	int result;

	pw = getpwnam(user);
	if (pw == NULL) {
		if (errno != 0)
			i_error("getpwnam(%s) failed: %m", user);
		else if (verbose)
			i_info("passwd(%s): unknown user", user);
		return FALSE;
	}

	if (!IS_VALID_PASSWD(pw->pw_passwd)) {
		if (verbose) {
			i_info("passwd(%s): invalid password field '%s'",
			       user, pw->pw_passwd);
		}
		return FALSE;
	}

	/* check if the password is valid */
	result = strcmp(mycrypt(password, pw->pw_passwd), pw->pw_passwd) == 0;

	/* clear the passwords from memory */
	safe_memset(pw->pw_passwd, 0, strlen(pw->pw_passwd));

	if (!result) {
		if (verbose)
			i_info("passwd(%s): password mismatch", user);
		return FALSE;
	}

	/* password ok, save the user info */
        passwd_fill_cookie_reply(pw, reply);
	return TRUE;
}

static void passwd_deinit(void)
{
	endpwent();
}

struct user_info_module userinfo_passwd = {
	NULL,
	passwd_deinit,

	passwd_verify_plain,
	NULL
};

#endif
