/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "process-title.h"

#ifdef HAVE_LIBBSD
#include <bsd/unistd.h>
#else
#include <unistd.h> /* FreeBSD */
#endif

static char *process_name = NULL;
static char *current_process_title;

#ifdef HAVE_SETPROCTITLE
#  undef PROCTITLE_HACK
#endif

#ifdef PROCTITLE_HACK

#ifdef DEBUG
/* if there are problems with this approach, try to make sure we notice it */
#  define PROCTITLE_CLEAR_CHAR 0xab
#else
/* There are always race conditions when updating the process title. ps might
   read a partially written title. Try to at least minimize this by using NUL
   as the fill character, so ps won't show a large number of 0xab chars. */
#  define PROCTITLE_CLEAR_CHAR 0
#endif

static char *process_title;
static size_t process_title_len, process_title_clean_pos;
static void *argv_memblock, *environ_memblock;

static void proctitle_hack_init(char *argv[], char *env[])
{
	char *last;
	unsigned int i;
	bool clear_env;

	i_assert(argv[0] != NULL);

	/* find the last argv or environment string. it should always be the
	   last string in environ, but don't rely on it. this is what openssh
	   does, so hopefully it's safe enough. */
	last = argv[0] + strlen(argv[0]) + 1;
	for (i = 1; argv[i] != NULL; i++) {
		if (argv[i] == last)
			last = argv[i] + strlen(argv[i]) + 1;
	}
	if (env[0] == NULL)
		clear_env = FALSE;
	else {
		clear_env = last == env[0];
		for (i = 0; env[i] != NULL; i++) {
			if (env[i] == last)
				last = env[i] + strlen(env[i]) + 1;
		}
	}

	process_title = argv[0];
	process_title_len = last - argv[0];

	if (clear_env) {
		memset(env[0], PROCTITLE_CLEAR_CHAR, last - env[0]);
		process_title_clean_pos = env[0] - process_title;
	} else {
		process_title_clean_pos = 0;
	}
}

static char **argv_dup(char *old_argv[], void **memblock_r)
{
	/* @UNSAFE */
	void *memblock, *memblock_end;
	char **new_argv;
	unsigned int i, count;
	size_t len, memblock_len = 0;

	for (count = 0; old_argv[count] != NULL; count++)
		memblock_len += strlen(old_argv[count]) + 1;
	memblock_len += sizeof(char *) * (count + 1);

	memblock = malloc(memblock_len);
	if (memblock == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "malloc() failed: %m");
	*memblock_r = memblock;
	memblock_end = PTR_OFFSET(memblock, memblock_len);

	new_argv = memblock;
	memblock = PTR_OFFSET(memblock, sizeof(char *) * (count + 1));

	for (i = 0; i < count; i++) {
		new_argv[i] = memblock;
		len = strlen(old_argv[i]) + 1;
		memcpy(memblock, old_argv[i], len);
		memblock = PTR_OFFSET(memblock, len);
	}
	i_assert(memblock == memblock_end);
	new_argv[i] = NULL;
	return new_argv;
}

static void proctitle_hack_set(const char *title)
{
	size_t len = strlen(title);

	/* OS X wants two NULs */
	if (len >= process_title_len-1)
		len = process_title_len - 2;

	memcpy(process_title, title, len);
	process_title[len++] = '\0';
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

void process_title_init(int argc ATTR_UNUSED, char **argv[])
{
#ifdef PROCTITLE_HACK
	char ***environ_p = env_get_environ_p();
	char **orig_argv = *argv;
	char **orig_environ = *environ_p;

	*argv = argv_dup(orig_argv, &argv_memblock);
	*environ_p = argv_dup(orig_environ, &environ_memblock);
	proctitle_hack_init(orig_argv, orig_environ);
#endif
#ifdef HAVE_LIBBSD
	setproctitle_init(argc, *argv, *env_get_environ_p());
#endif
	process_name = (*argv)[0];
}

void process_title_set(const char *title)
{
	i_assert(process_name != NULL);

	i_free(current_process_title);
	current_process_title = i_strdup(title);
#ifdef HAVE_SETPROCTITLE
	if (title == NULL)
		setproctitle(NULL);
	else
		setproctitle("%s", title);
#elif defined(PROCTITLE_HACK)
	T_BEGIN {
		proctitle_hack_set(t_strconcat(process_name, " ", title, NULL));
	} T_END;
#endif
}

const char *process_title_get(void)
{
	return current_process_title;
}

void process_title_deinit(void)
{
#ifdef PROCTITLE_HACK
	char ***environ_p = env_get_environ_p();

	free(argv_memblock);
	free(environ_memblock);

	/* Environment is no longer usable. Make sure we won't crash in case
	   some library's deinit function still calls getenv(). This code was
	   mainly added because of GNUTLS where we don't really care about the
	   getenv() call.

	   Alternatively we could remove the free() calls above, but that would
	   annoy memory leak checking tools. Also we could attempt to restore
	   the environ_p to its original state, but that's a bit complicated. */
	*environ_p = NULL;
#endif
	i_free(current_process_title);
}
