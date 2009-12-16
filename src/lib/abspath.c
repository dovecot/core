/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "abspath.h"

#include <unistd.h>

const char *t_abspath(const char *path)
{
	const char *dir;

	if (*path == '/')
		return path;

	if (t_get_current_dir(&dir) < 0)
		i_fatal("getcwd() failed: %m");
	return t_strconcat(dir, "/", path, NULL);
}

const char *t_abspath_to(const char *path, const char *root)
{
	if (*path == '/')
		return path;

	return t_strconcat(root, "/", path, NULL);
}

int t_get_current_dir(const char **dir_r)
{
	/* @UNSAFE */
	char *dir;
	size_t size = 128;

	dir = t_buffer_get(size);
	while (getcwd(dir, size) == NULL) {
		if (errno != ERANGE)
			return -1;
		size = nearest_power(size+1);
		dir = t_buffer_get(size);
	}
	t_buffer_alloc(strlen(dir) + 1);
	*dir_r = dir;
	return 0;
}
