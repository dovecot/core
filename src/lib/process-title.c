/* Copyright (c) 2002-2003 Timo Sirainen */

/*
   LINUX_PROCTITLE_HACK code from:
   http://lightconsulting.com/~thalakan/process-title-notes.html
*/

#include "lib.h"
#include "process-title.h"

#include <stdlib.h> /* NetBSD, OpenBSD */
#include <unistd.h> /* FreeBSD */

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
		i_fatal_status(FATAL_OUTOFMEM, "malloc() failed: %m");
	environ = p;

	for (i = 0; envp[i] != NULL; i++) {
		if ((environ[i] = strdup(envp[i])) == NULL)
			i_fatal_status(FATAL_OUTOFMEM, "strdup() failed: %m");
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
	i_strocpy(process_title, title, process_title_len);
}

#endif

void process_title_init(char *argv[] ATTR_UNUSED,
			char *envp[] ATTR_UNUSED)
{
#ifdef LINUX_PROCTITLE_HACK
	linux_proctitle_init(argv, envp);
#endif
	process_name = argv[0];
}

void process_title_set(const char *title ATTR_UNUSED)
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

