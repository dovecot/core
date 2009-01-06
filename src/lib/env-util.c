/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

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

void env_remove(const char *name)
{
	unsetenv(name);
}

void env_clean(void)
{
#ifdef HAVE_CLEARENV
	if (clearenv() < 0)
		i_fatal("clearenv() failed");
#else
	extern char **environ;

	/* Try to clear the environment.

	   a) environ = NULL crashes on OS X.
	   b) *environ = NULL doesn't work on FreeBSD 7.0.
	   c) environ = emptyenv doesn't work on Haiku OS
	   d) environ = calloc() should work everywhere
	*/
	environ = calloc(1, sizeof(*environ));
#endif
	/* don't clear the env_pool, otherwise the environment would get
	   corrupted if we failed to clear it. */
}
