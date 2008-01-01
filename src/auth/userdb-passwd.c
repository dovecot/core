/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"

#ifdef USERDB_PASSWD

#include "userdb.h"
#include "userdb-static.h"

#include <pwd.h>

#define USER_CACHE_KEY "%u"

struct passwd_userdb_module {
	struct userdb_module module;
	struct userdb_static_template *tmpl;
};

static void passwd_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct passwd_userdb_module *module =
		(struct passwd_userdb_module *)_module;
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
	userdb_static_template_export(module->tmpl, auth_request);

	if (!userdb_static_template_isset(module->tmpl, "system_user")) {
		auth_request_set_userdb_field(auth_request,
					      "system_user", pw->pw_name);
	}
	if (!userdb_static_template_isset(module->tmpl, "uid")) {
		auth_request_set_userdb_field(auth_request,
					      "uid", dec2str(pw->pw_uid));
	}
	if (!userdb_static_template_isset(module->tmpl, "gid")) {
		auth_request_set_userdb_field(auth_request,
					      "gid", dec2str(pw->pw_gid));
	}
	if (!userdb_static_template_isset(module->tmpl, "home"))
		auth_request_set_userdb_field(auth_request, "home", pw->pw_dir);

	callback(USERDB_RESULT_OK, auth_request);
}

static struct userdb_module *
passwd_passwd_preinit(struct auth_userdb *auth_userdb, const char *args)
{
	struct passwd_userdb_module *module;
	const char *value;

	module = p_new(auth_userdb->auth->pool, struct passwd_userdb_module, 1);
	module->module.cache_key = USER_CACHE_KEY;
	module->tmpl = userdb_static_template_build(auth_userdb->auth->pool,
						    "passwd", args);

	if (userdb_static_template_remove(module->tmpl, "blocking",
					  &value)) {
		module->module.blocking = value == NULL ||
			strcasecmp(value, "yes") == 0;
	}
	return &module->module;
}

struct userdb_module_interface userdb_passwd = {
	"passwd",

	passwd_passwd_preinit,
	NULL,
	NULL,

	passwd_lookup
};

#endif
