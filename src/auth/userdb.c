/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "auth-module.h"
#include "userdb.h"

#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

extern struct userdb_module userdb_passdb;
extern struct userdb_module userdb_static;
extern struct userdb_module userdb_passwd;
extern struct userdb_module userdb_passwd_file;
extern struct userdb_module userdb_vpopmail;
extern struct userdb_module userdb_ldap;
extern struct userdb_module userdb_sql;

struct userdb_module *userdbs[] = {
#ifdef USERDB_PASSWD
	&userdb_passwd,
#endif
#ifdef USERDB_PASSWD_FILE
	&userdb_passwd_file,
#endif
#ifdef USERDB_PASSDB
	&userdb_passdb,
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
	NULL
};

uid_t userdb_parse_uid(struct auth_request *request, const char *str)
{
	struct passwd *pw;

	if (str == NULL)
		return (uid_t)-1;

	if (*str >= '0' && *str <= '9')
		return (uid_t)strtoul(str, NULL, 10);

	pw = getpwnam(str);
	if (pw == NULL) {
		if (request != NULL) {
			auth_request_log_error(request, "userdb",
					       "Invalid UID field '%s'", str);
		}
		return (uid_t)-1;
	}
	return pw->pw_uid;
}

gid_t userdb_parse_gid(struct auth_request *request, const char *str)
{
	struct group *gr;

	if (str == NULL)
		return (uid_t)-1;

	if (*str >= '0' && *str <= '9')
		return (gid_t)strtoul(str, NULL, 10);

	gr = getgrnam(str);
	if (gr == NULL) {
		if (request != NULL) {
			auth_request_log_error(request, "userdb",
					       "Invalid GID field '%s'", str);
		}
		return (gid_t)-1;
	}
	return gr->gr_gid;
}

void userdb_preinit(struct auth *auth, const char *driver, const char *args)
{
	struct userdb_module **p;
        struct auth_userdb *auth_userdb, **dest;

	if (args == NULL) args = "";

	auth_userdb = p_new(auth->pool, struct auth_userdb, 1);
	auth_userdb->auth = auth;
	auth_userdb->args = p_strdup(auth->pool, args);

	for (dest = &auth->userdbs; *dest != NULL; dest = &(*dest)->next)
		auth_userdb->num++;
	*dest = auth_userdb;

	for (p = userdbs; *p != NULL; p++) {
		if (strcmp((*p)->name, driver) == 0) {
			auth_userdb->userdb = *p;
			break;
		}
	}
	
#ifdef HAVE_MODULES
	if (auth_userdb->userdb == NULL)
		auth_userdb->module = auth_module_open(driver);
	if (auth_userdb->module != NULL) {
		auth_userdb->userdb =
			auth_module_sym(auth_userdb->module,
					t_strconcat("userdb_", driver, NULL));
	}
#endif

	if (auth_userdb->userdb == NULL)
		i_fatal("Unknown userdb driver '%s'", driver);

	if (auth_userdb->userdb->preinit != NULL)
		auth_userdb->userdb->preinit(auth_userdb->args);
}

void userdb_init(struct auth_userdb *userdb)
{
	if (userdb->userdb->init != NULL)
		userdb->userdb->init(userdb->args);
}

void userdb_deinit(struct auth_userdb *userdb)
{
	if (userdb->userdb->deinit != NULL)
		userdb->userdb->deinit();
#ifdef HAVE_MODULES
	if (userdb->module != NULL)
                auth_module_close(userdb->module);
#endif
}
