/* Copyright (C) 2002 Timo Sirainen */

/* Thanks to Courier-IMAP for showing how the vpopmail API should be used */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERINFO_VPOPMAIL

#include "userinfo-passwd.h"

#include <stdio.h>
#include <vpopmail.h>
#include <vauth.h>

/* Limit user and domain to 80 chars each (+1 for \0). I wouldn't recommend
   raising this limit at least much, vpopmail is full of potential buffer
   overflows. */
#define VPOPMAIL_LIMIT 81

static int vpopmail_verify_plain(const char *user, const char *password,
				 AuthCookieReplyData *reply)
{
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
	char *passdup;
	int result;

	if (parse_email(t_strdup_noconst(user), vpop_user, vpop_domain,
			sizeof(vpop_user)-1) < 0)
		return FALSE;

	/* we have to get uid/gid separately, because the gid field in
	   struct vqpasswd isn't really gid at all but just some flags... */
	if (vget_assign(vpop_domain, NULL, 0,
			&reply->uid, &reply->gid) == NULL)
		return FALSE;

	vpw = vauth_getpw(vpop_user, vpop_domain);
	if (vpw != NULL && (vpw->pw_dir == NULL || vpw->pw_dir[0] == '\0')) {
		/* user's homedir doesn't exist yet, create it */
		if (make_user_dir(vpop_user, vpop_domain,
				  reply->uid, reply->gid) == NULL)
			return FALSE;

		vpw = vauth_getpw(vpop_user, vpop_domain);
	}

	if (vpw == NULL || (vpw->pw_gid & NO_IMAP))
		return FALSE;

	/* verify password */
        passdup = t_strdup_noconst(password);
	result = strcmp(crypt(passdup, vpw->pw_passwd), vpw->pw_passwd) == 0;

	memset(passdup, 0, strlen(passdup));
	memset(vpw->pw_passwd, 0, strlen(vpw->pw_passwd));

	if (!result)
		return FALSE;

	/* make sure it's not giving too large values to us */
	if (strlen(vpw->pw_dir) >= sizeof(reply->home)) {
		i_panic("Home directory too large (%u > %u)",
			strlen(vpw->pw_dir), sizeof(reply->home)-1);
	}

	if (strlen(vpw->pw_name) >= sizeof(reply->user)) {
		i_panic("Username too large (%u > %u)",
			strlen(vpw->pw_name), sizeof(reply->user)-1);
	}

	strcpy(reply->user, vpw->pw_name);
	strcpy(reply->home, vpw->pw_dir);

	return TRUE;
}

static void vpopmail_deinit(void)
{
	vclose();
}

UserInfoModule userinfo_vpopmail = {
	NULL,
	vpopmail_deinit,

	vpopmail_verify_plain,
	NULL
};

#endif
