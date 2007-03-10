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
	struct auth_stream_reply *reply;

	auth_request_log_debug(auth_request, "passwd", "lookup");

	pw = getpwnam(auth_request->user);
	if (pw == NULL) {
		auth_request_log_info(auth_request, "passwd", "unknown user");
		callback(USERDB_RESULT_USER_UNKNOWN, NULL, auth_request);
		return;
	}

	if (strcasecmp(pw->pw_name, auth_request->user) != 0) {
		/* try to catch broken NSS implementations (nss_ldap) */
		i_fatal("BROKEN NSS IMPLEMENTATION: "
			"getpwnam() lookup returned different user than was "
			"requested (%s != %s).",
			pw->pw_name, auth_request->user);
	}

	reply = auth_stream_reply_init(auth_request);
	auth_stream_reply_add(reply, NULL, pw->pw_name);
	auth_stream_reply_add(reply, "system_user", pw->pw_name);
	auth_stream_reply_add(reply, "uid", dec2str(pw->pw_uid));
	auth_stream_reply_add(reply, "gid", dec2str(pw->pw_gid));
	auth_stream_reply_add(reply, "home", pw->pw_dir);

	callback(USERDB_RESULT_OK, reply, auth_request);
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
