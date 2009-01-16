/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-error.h"

#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

bool mail_error_from_errno(enum mail_error *error_r,
			   const char **error_string_r)
{
	if (ENOACCESS(errno)) {
		*error_r = MAIL_ERROR_PERM;
		*error_string_r = MAIL_ERRSTR_NO_PERMISSION;
	} else if (ENOSPACE(errno)) {
		*error_r = MAIL_ERROR_NOSPACE;
		*error_string_r = MAIL_ERRSTR_NO_SPACE;
	} else if (ENOTFOUND(errno)) {
		*error_r = MAIL_ERROR_NOTFOUND;
		*error_string_r = errno != ELOOP ? "Not found" :
			"Directory structure is broken";
	} else {
		return FALSE;
	}
	return TRUE;
}

const char *mail_error_eacces_msg(const char *func, const char *path)
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
		if (ret == 0 || errno != EACCES)
			break;
		prev_path = dir;
		dir = "/";
	}

	if (ret == 0) {
		if (access(dir, X_OK) < 0 && errno == EACCES)
			str_printfa(errmsg, " missing +x perm: %s", dir);
		else if (prev_path == path &&
			 access(path, R_OK) < 0 && errno == EACCES)
			str_printfa(errmsg, " missing +r perm: %s", path);
		else
			str_printf(errmsg, " UNIX perms seem ok, ACL problem?");
	}
	str_append_c(errmsg, ')');
	return str_c(errmsg);
}
