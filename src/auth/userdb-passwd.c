/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_PASSWD

#include "common.h"
#include "userdb.h"

#include <pwd.h>

static void passwd_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback, void *context)
{
	struct user_data data;
	struct passwd *pw;

	pw = getpwnam(auth_request->user);
	if (pw == NULL) {
		if (verbose) {
			i_info("passwd(%s): unknown user",
			       get_log_prefix(auth_request));
		}
		callback(NULL, context);
		return;
	}

	memset(&data, 0, sizeof(data));
	data.uid = pw->pw_uid;
	data.gid = pw->pw_gid;

	data.virtual_user = data.system_user = pw->pw_name;
	data.home = pw->pw_dir;

	callback(&data, context);
}

struct userdb_module userdb_passwd = {
	NULL, NULL,
	passwd_lookup
};

#endif
