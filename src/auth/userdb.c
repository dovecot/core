/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "auth-module.h"
#include "auth-worker-server.h"
#include "userdb.h"

#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

extern struct userdb_module_interface userdb_prefetch;
extern struct userdb_module_interface userdb_static;
extern struct userdb_module_interface userdb_passwd;
extern struct userdb_module_interface userdb_passwd_file;
extern struct userdb_module_interface userdb_vpopmail;
extern struct userdb_module_interface userdb_ldap;
extern struct userdb_module_interface userdb_sql;
extern struct userdb_module_interface userdb_nss;

struct userdb_module_interface *userdb_interfaces[] = {
#ifdef USERDB_PASSWD
	&userdb_passwd,
#endif
#ifdef USERDB_PASSWD_FILE
	&userdb_passwd_file,
#endif
#ifdef USERDB_PREFETCH
	&userdb_prefetch,
#endif
#ifdef USERDB_STATIC
	&userdb_static,
#endif
#ifdef USERDB_VPOPMAIL
	&userdb_vpopmail,
#endif
#ifdef USERDB_LDAP
	&userdb_ldap,
#endif
#ifdef USERDB_SQL
	&userdb_sql,
#endif
#ifdef USERDB_NSS
	&userdb_nss,
#endif
	NULL
};

uid_t userdb_parse_uid(struct auth_request *request, const char *str)
{
	struct passwd *pw;
	uid_t uid;
	char *p;

	if (str == NULL)
		return (uid_t)-1;

	if (*str >= '0' && *str <= '9') {
		uid = (uid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return uid;
	}

	pw = getpwnam(str);
	if (pw == NULL) {
		if (request != NULL) {
			auth_request_log_error(request, "userdb",
					       "Invalid UID value '%s'", str);
		}
		return (uid_t)-1;
	}
	return pw->pw_uid;
}

gid_t userdb_parse_gid(struct auth_request *request, const char *str)
{
	struct group *gr;
	gid_t gid;
	char *p;

	if (str == NULL)
		return (gid_t)-1;

	if (*str >= '0' && *str <= '9') {
		gid = (gid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return gid;
	}

	gr = getgrnam(str);
	if (gr == NULL) {
		if (request != NULL) {
			auth_request_log_error(request, "userdb",
					       "Invalid GID value '%s'", str);
		}
		return (gid_t)-1;
	}
	return gr->gr_gid;
}

void userdb_preinit(struct auth *auth, const char *driver, const char *args)
{
	struct userdb_module_interface **p, *iface;
        struct auth_userdb *auth_userdb, **dest;

	if (args == NULL) args = "";

	auth_userdb = p_new(auth->pool, struct auth_userdb, 1);
	auth_userdb->auth = auth;
	auth_userdb->args = p_strdup(auth->pool, args);

	for (dest = &auth->userdbs; *dest != NULL; dest = &(*dest)->next)
		auth_userdb->num++;
	*dest = auth_userdb;

	iface = NULL;
	for (p = userdb_interfaces; *p != NULL; p++) {
		if (strcmp((*p)->name, driver) == 0) {
			iface = *p;
			break;
		}
	}
	
#ifdef HAVE_MODULES
	if (auth_userdb->userdb == NULL)
		auth_userdb->module = auth_module_open(driver);
	if (auth_userdb->module != NULL) {
		iface = auth_module_sym(auth_userdb->module,
					t_strconcat("userdb_", driver, NULL));
	}
#endif

	if (iface == NULL) {
		i_fatal("Unknown userdb driver '%s' "
			"(typo, or Dovecot was built without support for it? "
			"Check with dovecot --build-options)",
			driver);
	}

	if (iface->preinit == NULL) {
		auth_userdb->userdb =
			p_new(auth->pool, struct userdb_module, 1);
	} else {
		auth_userdb->userdb =
			iface->preinit(auth_userdb, auth_userdb->args);
	}
	auth_userdb->userdb->iface = iface;
}

void userdb_init(struct auth_userdb *userdb)
{
	if (userdb->userdb->iface->init != NULL)
		userdb->userdb->iface->init(userdb->userdb, userdb->args);

	if (userdb->userdb->blocking && !worker) {
		/* blocking userdb - we need an auth server */
		auth_worker_server_init();
	}
}

void userdb_deinit(struct auth_userdb *userdb)
{
	if (userdb->userdb->iface->deinit != NULL)
		userdb->userdb->iface->deinit(userdb->userdb);
#ifdef HAVE_MODULES
	if (userdb->module != NULL)
                auth_module_close(&userdb->module);
#endif
}
