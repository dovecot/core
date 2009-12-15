/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"

#include <stdlib.h>

struct env_backup {
	pool_t pool;
	const char **strings;
};

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
#ifdef UNSETENV_RET_INT
	if (unsetenv(name) < 0)
		i_fatal("unsetenv(%s) failed: %m", name);
#else
	unsetenv(name);
#endif
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

struct env_backup *env_backup_save(void)
{
	struct env_backup *env;
	extern char **environ;
	unsigned int i, count;
	pool_t pool;

	for (count = 0; environ[count] != NULL; count++) ;

	pool = pool_alloconly_create("saved environment", 4096);
	env = p_new(pool, struct env_backup, 1);
	env->pool = pool;
	env->strings = p_new(pool, const char *, count + 1);
	for (i = 0; i < count; i++)
		env->strings[i] = p_strdup(pool, environ[i]);
	return env;
}

void env_backup_restore(struct env_backup *env)
{
	unsigned int i;

	env_clean();
	for (i = 0; env->strings[i] != NULL; i++)
		env_put(env->strings[i]);
}

void env_backup_free(struct env_backup **_env)
{
	struct env_backup *env = *_env;

	*_env = NULL;
	pool_unref(&env->pool);
}

void env_deinit(void)
{
	if (env_pool != NULL)
		pool_unref(&env_pool);
}
