/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"

#ifdef USERDB_PASSWD

#include "userdb.h"

#include <pwd.h>

#define USER_CACHE_KEY "%u"

static void passwd_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback)
{
	struct passwd *pw;

	auth_request_log_debug(auth_request, "passwd", "lookup");

	pw = getpwnam(auth_request->user);
	if (pw == NULL) {
		auth_request_log_info(auth_request, "passwd", "unknown user");
		callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
		return;
	}

	if (strcasecmp(pw->pw_name, auth_request->user) != 0) {
		/* try to catch broken NSS implementations (nss_ldap) */
		i_fatal("BROKEN NSS IMPLEMENTATION: "
			"getpwnam() lookup returned different user than was "
			"requested (%s != %s).",
			pw->pw_name, auth_request->user);
	}

	auth_request_set_field(auth_request, "user", pw->pw_name, NULL);

	auth_request_init_userdb_reply(auth_request);
	auth_request_set_userdb_field(auth_request, "system_user", pw->pw_name);
	auth_request_set_userdb_field(auth_request, "uid", dec2str(pw->pw_uid));
	auth_request_set_userdb_field(auth_request, "gid", dec2str(pw->pw_gid));
	auth_request_set_userdb_field(auth_request, "home", pw->pw_dir);

	callback(USERDB_RESULT_OK, auth_request);
}

static void passwd_passwd_init(struct userdb_module *module,
			       const char *args)
{
	if (strcmp(args, "blocking=yes") == 0)
		module->blocking = TRUE;
	module->cache_key = USER_CACHE_KEY;
}

struct userdb_module_interface userdb_passwd = {
	"passwd",

	NULL,
	passwd_passwd_init,
	NULL,

	passwd_lookup
};

#endif
