/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "abspath.h"

#include <unistd.h>

const char *t_abspath(const char *path)
{
	char dir[PATH_MAX];

	if (*path == '/')
		return path;

	if (getcwd(dir, sizeof(dir)) == NULL)
		i_fatal("getcwd() failed: %m");
	return t_strconcat(dir, "/", path, NULL);
}

const char *t_abspath_to(const char *path, const char *root)
{
	if (*path == '/')
		return path;

	return t_strconcat(root, "/", path, NULL);
}
