/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "eacces-error.h"

#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

static const char *
eacces_error_get_full(const char *func, const char *path, bool creating)
{
	const char *prev_path = path, *dir = "/", *p;
	const struct passwd *pw;
	const struct group *group;
	string_t *errmsg;
	struct stat st;
	int ret = -1;

	errmsg = t_str_new(256);
	str_printfa(errmsg, "%s(%s) failed: Permission denied (euid=%s",
		    func, path, dec2str(geteuid()));

	pw = getpwuid(geteuid());
	if (pw != NULL)
		str_printfa(errmsg, "(%s)", pw->pw_name);

	str_printfa(errmsg, " egid=%s", dec2str(getegid()));
	group = getgrgid(getegid());
	if (group != NULL)
		str_printfa(errmsg, "(%s)", group->gr_name);

	while ((p = strrchr(prev_path, '/')) != NULL) {
		dir = t_strdup_until(prev_path, p);
		ret = stat(dir, &st);
		if (ret == 0)
			break;
		if (errno == EACCES) {
			/* see if we have access to parent directory */
		} else if (errno == ENOENT && creating) {
			/* probably mkdir_parents() failed here, find the first
			   parent directory we couldn't create */
		} else {
			/* some other error, can't handle it */
			str_printfa(errmsg, " stat(%s) failed: %m", dir);
			break;
		}
		prev_path = dir;
		dir = "/";
	}

	if (ret == 0) {
		/* dir is the first parent directory we can stat() */
		if (access(dir, X_OK) < 0) {
			if (errno == EACCES)
				str_printfa(errmsg, " missing +x perm: %s", dir);
			else
				str_printfa(errmsg, " access(%s, x) failed: %m", dir);
		} else if (creating && access(dir, W_OK) < 0) {
			if (errno == EACCES)
				str_printfa(errmsg, " missing +w perm: %s", dir);
			else
				str_printfa(errmsg, " access(%s, w) failed: %m", dir);
		} else if (prev_path == path && access(path, R_OK) < 0) {
			if (errno == EACCES)
				str_printfa(errmsg, " missing +r perm: %s", path);
			else
				str_printfa(errmsg, " access(%s, r) failed: %m", path);
		} else
			str_printfa(errmsg, " UNIX perms seem ok, ACL problem?");
	}
	str_append_c(errmsg, ')');
	return str_c(errmsg);
}

const char *eacces_error_get(const char *func, const char *path)
{
	return eacces_error_get_full(func, path, FALSE);
}

const char *eacces_error_get_creating(const char *func, const char *path)
{
	return eacces_error_get_full(func, path, TRUE);
}
