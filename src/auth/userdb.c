/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "auth-module.h"
#include "userdb.h"

#include <stdlib.h>

#ifdef HAVE_MODULES
static struct auth_module *userdb_module = NULL;
#endif

struct userdb_module *userdb;
static char *userdb_args;

void userdb_preinit(void)
{
	const char *name, *args;

	userdb = NULL;

	name = getenv("USERDB");
	if (name == NULL)
		i_fatal("USERDB environment is unset");

	args = strchr(name, ' ');
	name = t_strcut(name, ' ');

	if (args == NULL) args = "";
	while (*args == ' ' || *args == '\t')
		args++;

	userdb_args = i_strdup(args);

#ifdef USERDB_PASSWD
	if (strcasecmp(name, "passwd") == 0)
		userdb = &userdb_passwd;
#endif
#ifdef USERDB_PASSWD_FILE
	if (strcasecmp(name, "passwd-file") == 0)
		userdb = &userdb_passwd_file;
#endif
#ifdef USERDB_STATIC
	if (strcasecmp(name, "static") == 0)
		userdb = &userdb_static;
#endif
#ifdef USERDB_VPOPMAIL
	if (strcasecmp(name, "vpopmail") == 0)
		userdb = &userdb_vpopmail;
#endif
#ifdef USERDB_LDAP
	if (strcasecmp(name, "ldap") == 0)
		userdb = &userdb_ldap;
#endif
#ifdef USERDB_SQL
	if (strcasecmp(name, "sql") == 0)
		userdb = &userdb_sql;
#endif
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
