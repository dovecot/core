/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"

#include <stdlib.h>

static pool_t pool = NULL;

void env_put(const char *env)
{
	if (pool == NULL) {
		pool = pool_alloconly_create(MEMPOOL_GROWING"Environment",
					     2048);
	}
	if (putenv(p_strdup(pool, env)) != 0)
		i_fatal("putenv(%s) failed: %m", env);
}

void env_clean(void)
{
#ifdef HAVE_CLEARENV
	if (clearenv() < 0)
		i_fatal("clearenv() failed");
#else
	extern char **environ;
	static char *emptyenv[1] = { NULL };

	/* Try to clear the environment.

	   a) environ = NULL crashes on OS X.
	   b) *environ = NULL doesn't work on FreeBSD 7.0.
	   c) environ = emptyenv appears to work everywhere.
	*/
	environ = emptyenv;
#endif
	/* don't clear the env_pool, otherwise the environment would get
	   corrupted if we failed to clear it. */
}
