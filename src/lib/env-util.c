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
	extern char **environ;

	/* Try to clear the environment. It should always be non-NULL, but
	   apparently it's not on some ancient OSes (Ultrix), so just keep
	   the check. The clearing also fails on FreeBSD 7.0 (currently). */
	if (environ != NULL)
		*environ = NULL;

	/* don't clear the env_pool, otherwise the environment would get
	   corrupted if we failed to clear it. */
}
