/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "auth-module.h"
#include "userdb.h"

#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#ifdef HAVE_MODULES
static struct auth_module *userdb_module = NULL;
#endif

struct userdb_module *userdbs[] = {
#ifdef USERDB_PASSWD
	&userdb_passwd,
#endif
#ifdef USERDB_PASSWD_FILE
	&userdb_passwd_file,
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

struct userdb_module *userdb;
static char *userdb_args;

uid_t userdb_parse_uid(struct auth_request *request, const char *str)
{
	struct passwd *pw;

	if (*str >= '0' && *str <= '9')
		return (uid_t)strtoul(str, NULL, 10);

	pw = getpwnam(str);
	if (pw == NULL) {
		if (request != NULL) {
			i_error("userdb(%s): Invalid UID field '%s'",
				get_log_prefix(request), str);
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
			i_error("userdb(%s): Invalid GID field '%s'",
				get_log_prefix(request), str);
		}
		return (gid_t)-1;
	}
	return gr->gr_gid;
}

void userdb_preinit(void)
{
	struct userdb_module **p;
	const char *name, *args;

	name = getenv("USERDB");
	if (name == NULL)
		i_fatal("USERDB environment is unset");

	args = strchr(name, ' ');
	name = t_strcut(name, ' ');

	if (args == NULL) args = "";
	while (*args == ' ' || *args == '\t')
		args++;

	userdb_args = i_strdup(args);

	userdb = NULL;
	for (p = userdbs; *p != NULL; p++) {
		if (strcmp((*p)->name, name) == 0) {
			userdb = *p;
			break;
		}
	}
#ifdef HAVE_MODULES
	userdb_module = userdb != NULL ? NULL : auth_module_open(name);
	if (userdb_module != NULL) {
		userdb = auth_module_sym(userdb_module,
					 t_strconcat("userdb_", name, NULL));
	}
#endif

	if (userdb == NULL)
		i_fatal("Unknown userdb type '%s'", name);

	if (userdb->preinit != NULL)
		userdb->preinit(args);
}

void userdb_init(void)
{
	if (userdb->init != NULL)
		userdb->init(userdb_args);
}

void userdb_deinit(void)
{
	if (userdb != NULL && userdb->deinit != NULL)
		userdb->deinit();
#ifdef HAVE_MODULES
	if (userdb_module != NULL)
                auth_module_close(userdb_module);
#endif
	i_free(userdb_args);
}
