/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_PASSWD

#include "common.h"
#include "userdb.h"

#include <pwd.h>

static void passwd_lookup(const char *user, userdb_callback_t *callback,
			  void *context)
{
	struct user_data data;
	struct passwd *pw;
	size_t len;

	pw = getpwnam(user);
	if (pw == NULL) {
		if (errno != 0)
			i_error("getpwnam(%s) failed: %m", user);
		else if (verbose)
			i_info("passwd(%s): unknown user", user);
		callback(NULL, context);
		return;
	}

	memset(&data, 0, sizeof(data));
	data.uid = pw->pw_uid;
	data.gid = pw->pw_gid;

	data.virtual_user = data.system_user = pw->pw_name;

	len = strlen(pw->pw_dir);
	if (len < 3 || strcmp(pw->pw_dir + len - 3, "/./") != 0)
		data.home = pw->pw_dir;
	else {
		/* wu-ftpd uses <chroot>/./<dir>. We don't support
		   the dir after chroot, but this should work well enough. */
		data.home = t_strndup(pw->pw_dir, len-3);
		data.chroot = TRUE;
	}

	callback(&data, context);
}

struct userdb_module userdb_passwd = {
	NULL, NULL,
	passwd_lookup
};

#endif
