/*
    Copyright (c) 2002 Timo Sirainen

    LINUX_PROCTITLE_HACK code from:
    http://lightconsulting.com/~thalakan/process-title-notes.html

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
#include "process-title.h"

/* NOTE: This really is a horrible hack, I don't recommend using it for
   anything else than debugging. */
/*#define LINUX_PROCTITLE_HACK*/

static char *process_name = NULL;

#ifdef LINUX_PROCTITLE_HACK
static char *process_title;
static size_t process_title_len;

static void linux_proctitle_init(char *argv[], char *envp[])
{
	extern char **environ;
	char **p;
	int i;

	/* copy environment elsewhere */
	for (i = 0; envp[i] != NULL; i++)
		;

	if ((p = malloc((i + 1) * sizeof(char *))) == NULL)
		i_panic("malloc() failed: %m");
	environ = p;

	for (i = 0; envp[i] != NULL; i++) {
		if ((environ[i] = strdup(envp[i])) == NULL)
			i_panic("malloc() failed: %m");
	}
	environ[i] = NULL;

	/* memory is allocated so that argv[] comes first, environment next.
	   Calculate the max. size for process name with by checking the
	   address for last environment and it's length. */
	process_title = argv[0];
	process_title_len = (size_t) (envp[i-1] - argv[0]) + strlen(envp[i-1]);
}

static void linux_proctitle_set(const char *title)
{
	strocpy(process_title, title, process_title_len);
}

#endif

void process_title_init(char *argv[] __attr_unused__,
			char *envp[] __attr_unused__)
{
#ifdef LINUX_PROCTITLE_HACK
	linux_proctitle_init(argv, envp);
#endif
	process_name = argv[0];
}

void process_title_set(const char *title __attr_unused__)
{
	i_assert(process_name != NULL);

#ifdef HAVE_SETPROCTITLE
	if (title == NULL)
		setproctitle("%s", process_name);
	else
		setproctitle("%s %s", process_name, title);
#elif defined(LINUX_PROCTITLE_HACK)
	linux_proctitle_set(t_strconcat(process_name, " ", title, NULL));
#endif
}

