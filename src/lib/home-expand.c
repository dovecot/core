/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "home-expand.h"

#include <stdlib.h>
#include <pwd.h>

/* expand ~/ or ~user/ in beginning of path */
const char *home_expand(const char *path)
{
	const char *home, *p, *orig_path;
	struct passwd *pw;

	if (*path != '~')
		return path;

	orig_path = path++;
	if (*path == '/' || *path == '\0') {
		home = getenv("HOME");
		if (*path != '\0') path++;
	} else {
		p = strchr(path, '/');
		if (p == NULL) {
			pw = getpwnam(path);
			path = "";
		} else {
			pw = getpwnam(t_strdup_until(path, p));
			path = p+1;
		}

		home = pw == NULL ? NULL : pw->pw_dir;
	}

	if (home == NULL)
		return orig_path;
	else if (*path == '\0')
		return t_strdup(home);
	else
		return t_strconcat(home, "/", path, NULL);
}
