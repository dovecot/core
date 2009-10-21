/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

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

static char **argv_dup(char *old_argv[])
{
	char **new_argv;
	unsigned int i, count;

	for (count = 0; old_argv[count] != NULL; count++) ;

	new_argv = malloc(sizeof(char *) * (count + 1));
	for (i = 0; i < count; i++) {
		new_argv[i] = strdup(old_argv[i]);
		if (new_argv[i] == NULL)
			i_fatal_status(FATAL_OUTOFMEM, "strdup() failed: %m");
	}
	new_argv[i] = NULL;
	return new_argv;
}

static void linux_proctitle_set(const char *title)
{
	i_strocpy(process_title, title, process_title_len);
}

#endif

void process_title_init(char **argv[], char *envp[] ATTR_UNUSED)
{
#ifdef LINUX_PROCTITLE_HACK
	*argv = argv_dup(*argv);
	linux_proctitle_init(*argv, envp);
#endif
	process_name = (*argv)[0];
}

void process_title_set(const char *title ATTR_UNUSED)
{
	i_assert(process_name != NULL);

#ifdef HAVE_SETPROCTITLE
	if (title == NULL)
		setproctitle(NULL);
	else
		setproctitle("%s", title);
#elif defined(LINUX_PROCTITLE_HACK)
	linux_proctitle_set(t_strconcat(process_name, " ", title, NULL));
#endif
}
