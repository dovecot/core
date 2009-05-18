/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"

#include <stdlib.h>

static pool_t env_pool = NULL;

void env_put(const char *env)
{
	if (env_pool == NULL) {
		env_pool = pool_alloconly_create(MEMPOOL_GROWING"Environment",
						 2048);
	}
	if (putenv(p_strdup(env_pool, env)) != 0)
		i_fatal("putenv(%s) failed: %m", env);
}

void env_remove(const char *name)
{
#ifdef HAVE_UNSETENV
	unsetenv(name);
#else
	extern char **environ;
	unsigned int len;
	char **envp;

	len = strlen(name);
	for (envp = environ; *envp != NULL; envp++) {
		if (strncmp(name, *envp, len) == 0 &&
		    (*envp)[len] == '=') {
			do {
				envp[0] = envp[1];
			} while (*++envp != NULL);
			break;
		}
	}
#endif
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
	if (env_pool != NULL)
		p_clear(env_pool);
}
