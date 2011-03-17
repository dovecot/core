/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ipwd.h"
#include "home-expand.h"

#include <stdlib.h>

int home_try_expand(const char **_path)
{
	const char *path = *_path;
	const char *name, *home, *p;
	struct passwd pw;

	if (path == NULL || *path != '~')
		return 0;

	path++;
	if (*path == '/' || *path == '\0') {
		home = getenv("HOME");
		if (*path != '\0') path++;
	} else {
		p = strchr(path, '/');
		if (p == NULL) {
			name = path;
			path = "";
		} else {
			name = t_strdup_until(path, p);
			path = p+1;
		}
		switch (i_getpwnam(name, &pw)) {
		case -1:
			i_error("getpwnam(%s) failed: %m", name);
			home = NULL;
			break;
		case 0:
			home = NULL;
			break;
		default:
			home = pw.pw_dir;
			break;
		}
	}

	if (home == NULL)
		return -1;

	if (*path == '\0')
		*_path = t_strdup(home);
	else
		*_path = t_strconcat(home, "/", path, NULL);
	return 0;
}

const char *home_expand(const char *path)
{
	(void)home_try_expand(&path);
	return path;
}

const char *home_expand_tilde(const char *path, const char *home)
{
	if (path == NULL || *path != '~')
		return path;

	if (path[1] == '\0')
		return home;
	if (path[1] != '/')
		return path;

	/* ~/ used */
	return t_strconcat(home, path + 1, NULL);
}
