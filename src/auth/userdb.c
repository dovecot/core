/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "userdb.h"

#include <stdlib.h>

struct userdb_module *userdb;

void userdb_init(void)
{
	const char *name, *args;

	userdb = NULL;

	name = getenv("USERDB");
	if (name == NULL)
		i_fatal("USERDB environment is unset");

	args = strchr(name, ' ');
	name = t_strcut(name, ' ');

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

	if (userdb == NULL)
		i_fatal("Unknown userdb type '%s'", name);

	/* initialize */
	if (userdb->init != NULL)
		userdb->init(args != NULL ? args+1 : "");
}

void userdb_deinit(void)
{
	if (userdb != NULL && userdb->deinit != NULL)
		userdb->deinit();
}
