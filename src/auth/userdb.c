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

void userdb_preinit(struct auth *auth, const char *data)
{
	struct userdb_module **p;
	const char *name, *args;

	args = strchr(data, ' ');
	name = t_strcut(data, ' ');

	if (args == NULL) args = "";
	while (*args == ' ' || *args == '\t')
		args++;

	auth->userdb_args = i_strdup(args);

	for (p = userdbs; *p != NULL; p++) {
		if (strcmp((*p)->name, name) == 0) {
			auth->userdb = *p;
			break;
		}
	}
#ifdef HAVE_MODULES
	auth->userdb_module = auth->userdb != NULL ? NULL :
		auth_module_open(name);
	if (auth->userdb_module != NULL) {
		auth->userdb = auth_module_sym(auth->userdb_module,
					       t_strconcat("userdb_", name,
							   NULL));
	}
#endif

	if (auth->userdb == NULL)
		i_fatal("Unknown userdb type '%s'", name);

	if (auth->userdb->preinit != NULL)
		auth->userdb->preinit(args);
}

void userdb_init(struct auth *auth)
{
	if (auth->userdb->init != NULL)
		auth->userdb->init(auth->userdb_args);
}

void userdb_deinit(struct auth *auth)
{
	if (auth->userdb->deinit != NULL)
		auth->userdb->deinit();
#ifdef HAVE_MODULES
	if (auth->userdb_module != NULL)
                auth_module_close(auth->userdb_module);
#endif
	i_free(auth->userdb_args);
}
