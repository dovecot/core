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

void env_put(const char *name, const char *value)
{
	i_assert(strchr(name, '=') == NULL);

	if (setenv(name, value, 1) != 0)
		i_fatal("setenv(%s, %s) failed: %m", name, value);
}

void env_put_array(const char *const *envs)
{
	for (unsigned int i = 0; envs[i] != NULL; i++) {
		const char *value = strchr(envs[i], '=');
		i_assert(value != NULL);
		T_BEGIN {
			const char *name = t_strdup_until(envs[i], value++);
			env_put(name, value);
		} T_END;
	}
}

void env_remove(const char *name)
{
	if (unsetenv(name) < 0)
		i_fatal("unsetenv(%s) failed: %m", name);
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
}

static void env_clean_except_real(const char *const preserve_envs[])
{
	ARRAY_TYPE(const_string) copy;
	const char *value, *const *envp;
	unsigned int i, count;

	t_array_init(&copy, 16);
	for (i = 0; preserve_envs[i] != NULL; i++) {
		const char *key = preserve_envs[i];

		value = getenv(key);
		if (value != NULL) {
			key = t_strdup(key);
			value = t_strdup(value);
			array_push_back(&copy, &key);
			array_push_back(&copy, &value);
		}
	}

	/* Note that if the original environment was set with env_put(), the
	   environment strings will be invalid after env_clean(). That's why
	   we t_strdup() them above. */
	env_clean();

	envp = array_get(&copy, &count);
	for (i = 0; i < count; i += 2)
		env_put(envp[i], envp[i+1]);
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
	env_clean();
	env_put_array(env->strings);
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
