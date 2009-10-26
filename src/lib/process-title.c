/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "process-title.h"

#include <stdlib.h> /* NetBSD, OpenBSD */
#include <unistd.h> /* FreeBSD */

static char *process_name = NULL;

#ifdef HAVE_SETPROCTITLE
#  undef PROCTITLE_HACK
#endif

#ifdef PROCTITLE_HACK

#define PROCTITLE_CLEAR_CHAR 0xab

static char *process_title;
static size_t process_title_len, process_title_clean_pos;

static void proctitle_hack_init(char *argv[], char *env[])
{
	char *last;
	unsigned int i;
	bool clear_env;

	/* find the last argv or environment string. it should always be the
	   last string in environ, but don't rely on it. this is what openssh
	   does, so hopefully it's safe enough. */
	last = argv[0] + strlen(argv[0]) + 1;
	for (i = 1; argv[i] != NULL; i++) {
		if (argv[i] == last)
			last = argv[i] + strlen(argv[i]) + 1;
	}
	clear_env = last == env[0];
	for (i = 0; env[i] != NULL; i++) {
		if (env[i] == last)
			last = env[i] + strlen(env[i]) + 1;
	}

	process_title = argv[0];
	process_title_len = last - argv[0];

	/* if there are problems with this approach, try to make sure we
	   notice it */
	if (clear_env) {
		memset(env[0], PROCTITLE_CLEAR_CHAR, last - env[0]);
		process_title_clean_pos = env[0] - process_title;
	} else {
		process_title_clean_pos = 0;
	}
}

static char **argv_dup(char *old_argv[])
{
	char **new_argv;
	unsigned int i, count;

	for (count = 0; old_argv[count] != NULL; count++) ;

	new_argv = malloc(sizeof(char *) * (count + 1));
	if (new_argv == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "malloc() failed: %m");
	for (i = 0; i < count; i++) {
		new_argv[i] = strdup(old_argv[i]);
		if (new_argv[i] == NULL)
			i_fatal_status(FATAL_OUTOFMEM, "strdup() failed: %m");
	}
	new_argv[i] = NULL;
	return new_argv;
}

static void proctitle_hack_set(const char *title)
{
	size_t len = strlen(title);

	if (len >= process_title_len)
		len = process_title_len - 1;

	memcpy(process_title, title, len);
	process_title[len++] = '\0';

	if (len < process_title_clean_pos) {
		memset(process_title + len, PROCTITLE_CLEAR_CHAR,
		       process_title_clean_pos - len);
		process_title_clean_pos = len;
	} else if (process_title_clean_pos != 0) {
		process_title_clean_pos = len;
	}
}

#endif

void process_title_init(char **argv[])
{
#ifdef PROCTITLE_HACK
	extern char **environ;
	char **orig_argv = *argv;
	char **orig_environ = environ;

	*argv = argv_dup(orig_argv);
	environ = argv_dup(orig_environ);
	proctitle_hack_init(orig_argv, orig_environ);
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
#elif defined(PROCTITLE_HACK)
	proctitle_hack_set(t_strconcat(process_name, " ", title, NULL));
#endif
}
