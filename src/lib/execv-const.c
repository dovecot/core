/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "execv-const.h"

#include <unistd.h>

void execv_const(const char *path, const char *const argv[])
{
	(void)execv(path, (void *)argv);
	i_fatal_status(errno == ENOMEM ? FATAL_OUTOFMEM : FATAL_EXEC,
		       "execv(%s) failed: %m", path);
}

void execvp_const(const char *file, const char *const argv[])
{
	(void)execvp(file, (void *)argv);
	i_fatal_status(errno == ENOMEM ? FATAL_OUTOFMEM : FATAL_EXEC,
		       "execvp(%s) failed: %m", file);
}
