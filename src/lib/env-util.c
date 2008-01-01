/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "env-util.h"

#include <stdlib.h>

static pool_t pool = NULL;

void env_put(const char *env)
{
	if (pool == NULL)
		pool = pool_alloconly_create("Environment", 2048);

	if (putenv(p_strdup(pool, env)) != 0)
		i_fatal("putenv(%s) failed: %m", env);
}

void env_clean(void)
{
	extern char **environ;

	if (environ != NULL)
		*environ = NULL;

	if (pool != NULL)
		pool_unref(&pool);
}

void envarr_add(ARRAY_TYPE(const_string) *arr,
		const char *key, const char *value)
{
	const char *str = t_strconcat(key, "=", value, NULL);

	array_append(arr, &str, 1);
}

void envarr_addi(ARRAY_TYPE(const_string) *arr, const char *key,
		 unsigned int value)
{
	char str[MAX_INT_STRLEN];

	i_snprintf(str, sizeof(str), "%u", value);
	envarr_add(arr, key, str);
}

void envarr_addb(ARRAY_TYPE(const_string) *arr, const char *key)
{
	envarr_add(arr, key, "1");
}
