/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "execv-const.h"

#include <unistd.h>

static char **argv_drop_const(const char *const argv[])
{
	char **ret;
	unsigned int i, count;

	for (count = 0; argv[count] != NULL; count++) ;

	ret = t_new(char *, count + 1);
	for (i = 0; i < count; i++)
		ret[i] = t_strdup_noconst(argv[i]);
	return ret;
}

void execv_const(const char *path, const char *const argv[])
{
	(void)execv(path, argv_drop_const(argv));
	i_fatal_status(errno == ENOMEM ? FATAL_OUTOFMEM : FATAL_EXEC,
		       "execv(%s) failed: %m", path);
}

void execvp_const(const char *file, const char *const argv[])
{
	(void)execvp(file, argv_drop_const(argv));
	i_fatal_status(errno == ENOMEM ? FATAL_OUTOFMEM : FATAL_EXEC,
		       "execvp(%s) failed: %m", file);
}
