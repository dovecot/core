/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_PASSWD

#include "common.h"
#include "userdb.h"

#include <pwd.h>

static void passwd_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback)
{
	struct passwd *pw;
	const char *result;

	pw = getpwnam(auth_request->user);
	if (pw == NULL) {
		auth_request_log_info(auth_request, "passwd", "unknown user");
		callback(NULL, auth_request);
		return;
	}

	result = t_strdup_printf("%s\tsystem_user=%s\tuid=%s\tgid=%s\t"
				 "home=%s", pw->pw_name, pw->pw_name,
				 dec2str(pw->pw_uid), dec2str(pw->pw_gid),
				 pw->pw_dir);
	callback(result, auth_request);
}

struct userdb_module userdb_passwd = {
	"passwd",
	FALSE,

	NULL, NULL, NULL,
	passwd_lookup
};

#endif
