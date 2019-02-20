/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "env-util.h"

#ifdef __APPLE__
#  include <crt_externs.h>
#endif

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
	size_t len;
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
	char ***environ_p = env_get_environ_p();

	/* Try to clear the environment.

	   a) environ = NULL crashes on OS X.
	   b) *environ = NULL doesn't work on FreeBSD 7.0.
	   c) environ = emptyenv doesn't work on Haiku OS
	   d) environ = calloc() should work everywhere
	*/
	*environ_p = calloc(1, sizeof(**environ_p));
#endif
	if (env_pool != NULL)
		p_clear(env_pool);
}

static void env_clean_except_real(const char *const preserve_envs[])
{
	ARRAY_TYPE(const_string) copy;
	const char *value, *const *envp;
	unsigned int i;

	t_array_init(&copy, 16);
	for (i = 0; preserve_envs[i] != NULL; i++) {
		const char *key = preserve_envs[i];

		value = getenv(key);
		if (value != NULL) {
			value = t_strconcat(key, "=", value, NULL);
			array_push_back(&copy, &value);
		}
	}

	/* Note that if the original environment was set with env_put(), the
	   environment strings will be invalid after env_clean(). That's why
	   we t_strconcat() them above. */
	env_clean();

	array_foreach(&copy, envp)
		env_put(*envp);
}

void env_clean_except(const char *const preserve_envs[])
{
	T_BEGIN {
		env_clean_except_real(preserve_envs);
	} T_END;
}

struct env_backup *env_backup_save(void)
{
	char **environ = *env_get_environ_p();
	struct env_backup *env;
	unsigned int i, count;
	pool_t pool;

	i_assert(environ != NULL);

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

char ***env_get_environ_p(void)
{
#ifdef __APPLE__
	return _NSGetEnviron();
#else
	extern char **environ;

	return &environ;
#endif
}

void env_deinit(void)
{
	pool_unref(&env_pool);
}
