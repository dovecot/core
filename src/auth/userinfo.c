/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "userinfo.h"

#include <stdlib.h>

UserInfoModule *userinfo;

void userinfo_init(void)
{
	const char *name, *args;

	userinfo = NULL;

	name = getenv("USERINFO");
	if (name == NULL)
		i_fatal("USERINFO environment is unset");

#ifdef USERINFO_PASSWD
	if (strcasecmp(name, "passwd") == 0)
		userinfo = &userinfo_passwd;
#endif
#ifdef USERINFO_SHADOW
	if (strcasecmp(name, "shadow") == 0)
		userinfo = &userinfo_shadow;
#endif
#ifdef USERINFO_PAM
	if (strcasecmp(name, "pam") == 0)
		userinfo = &userinfo_pam;
#endif
#ifdef USERINFO_PASSWD_FILE
	if (strcasecmp(name, "passwd-file") == 0)
		userinfo = &userinfo_passwd_file;
#endif
#ifdef USERINFO_VPOPMAIL
	if (strcasecmp(name, "vpopmail") == 0)
		userinfo = &userinfo_vpopmail;
#endif

	if (userinfo == NULL)
		i_fatal("Unknown userinfo type '%s'", name);

	/* initialize */
	if (userinfo->init != NULL) {
		args = getenv("USERINFO_ARGS");
		if (args == NULL) args = "";

		userinfo->init(args);
	}

	if ((auth_methods & AUTH_METHOD_PLAIN) &&
	    userinfo->verify_plain == NULL)
		i_fatal("Userinfo %s doesn't support PLAIN method", name);
	if ((auth_methods & AUTH_METHOD_DIGEST_MD5) &&
	    userinfo->lookup_digest_md5 == NULL)
		i_fatal("Userinfo %s doesn't support DIGEST-MD5 method", name);
}

void userinfo_deinit(void)
{
	if (userinfo != NULL && userinfo->deinit != NULL)
		userinfo->deinit();
}
