/*
 env-util.c : Environment variable handling

    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "env-util.h"

#include <stdlib.h>

static pool_t pool = NULL;

void env_put(const char *env)
{
	if (pool == NULL)
		pool = pool_alloconly_create("Environment", 1024);

	if (putenv(p_strdup(pool, env)) != 0)
		i_fatal("Environment full, can't add: %s", env);
}

void env_remove(const char *env)
{
	extern char **environ;
	size_t len;

	if (environ == NULL)
		return;

	len = strlen(env);
	for (; *environ != NULL; environ++) {
		if (strncmp(*environ, env, len) == 0 &&
		    (*environ)[len] == '=') {
			char **p;

			for (p = environ; *p != NULL; p++)
				p[0] = p[1];
		}
	}
}

void env_clean(void)
{
	extern char **environ;

	if (environ != NULL)
		*environ = NULL;

	if (pool != NULL) {
		pool_unref(pool);
		pool = NULL;
	}
}
