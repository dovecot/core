/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "home-expand.h"

#include <stdlib.h>
#include <pwd.h>

int home_try_expand(const char **_path)
{
	const char *path = *_path;
	const char *home, *p, *orig_path;
	struct passwd *pw;

	if (path == NULL || *path != '~')
		return 0;

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
