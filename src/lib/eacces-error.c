/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "abspath.h"
#include "ipwd.h"
#include "restrict-access.h"
#include "eacces-error.h"

#include <sys/stat.h>
#include <unistd.h>

static bool is_in_group(gid_t gid)
{
	const gid_t *gids;
	unsigned int i, count;

	if (getegid() == gid)
		return TRUE;

	gids = restrict_get_groups_list(&count);
	for (i = 0; i < count; i++) {
		if (gids[i] == gid)
			return TRUE;
	}
	return FALSE;
}

static void write_eacces_error(string_t *errmsg, const char *path, int mode)
{
	char c;

	switch (mode) {
	case R_OK:
		c = 'r';
		break;
	case W_OK:
		c = 'w';
		break;
	case X_OK:
		c = 'x';
		break;
	default:
		i_unreached();
	}
	str_printfa(errmsg, " missing +%c perm: %s", c, path);
}

static int
test_manual_access(const char *path, int access_mode, bool write_eacces,
		   string_t *errmsg)
{
	const struct group *group;
	bool user_not_in_group = FALSE;
	struct stat st;
	int mode;

	if (stat(path, &st) < 0) {
		str_printfa(errmsg, " stat(%s) failed: %m", path);
		return -1;
	}

	switch (access_mode) {
	case R_OK:
		mode = 04;
		break;
	case W_OK:
		mode = 02;
		break;
	case X_OK:
		mode = 01;
		break;
	default:
		i_unreached();
	}

	if (st.st_uid == geteuid())
		st.st_mode = (st.st_mode & 0700) >> 6;
	else if (is_in_group(st.st_gid))
		st.st_mode = (st.st_mode & 0070) >> 3;
	else {
		if ((((st.st_mode & 0070) >> 3) & mode) != 0)
			user_not_in_group = TRUE;
		st.st_mode = (st.st_mode & 0007);
	}

	if ((st.st_mode & mode) != 0)
		return 0;

	if (write_eacces)
		write_eacces_error(errmsg, path, access_mode);
	if (user_not_in_group) {
		/* group would have had enough permissions,
		   but we don't belong to the group */
		str_printfa(errmsg, ", we're not in group %s",
			    dec2str(st.st_gid));
		group = getgrgid(st.st_gid);
		if (group != NULL)
			str_printfa(errmsg, "(%s)", group->gr_name);
	}
	errno = EACCES;
	return -1;
}

static int test_access(const char *path, int access_mode, string_t *errmsg)
{
	struct stat st;

	if (getuid() == geteuid()) {
		if (access(path, access_mode) == 0)
			return 0;
		if (errno == EACCES) {
			write_eacces_error(errmsg, path, access_mode);
			if (test_manual_access(path, access_mode,
					       FALSE, errmsg) == 0) {
				str_append(errmsg, ", UNIX perms appear ok "
					   "(ACL/MAC wrong?)");
			}
			errno = EACCES;
		} else {
			str_printfa(errmsg, ", access(%s, %d) failed: %m",
				    path, access_mode);
		}
		return -1;
	} 

	/* access() uses real uid, not effective uid.
	   we'll have to do these checks manually. */
	switch (access_mode) {
	case X_OK:
		if (stat(t_strconcat(path, "/test", NULL), &st) == 0)
			return 0;
		if (errno == ENOENT || errno == ENOTDIR)
			return 0;
		if (errno == EACCES)
			write_eacces_error(errmsg, path, access_mode);
		else
			str_printfa(errmsg, ", stat(%s/test) failed: %m", path);
		return -1;
	case R_OK:
	case W_OK:
		break;
	default:
		i_unreached();
	}

	return test_manual_access(path, access_mode, TRUE, errmsg);
}

static const char *
eacces_error_get_full(const char *func, const char *path, bool creating)
{
	const char *prev_path, *dir = NULL, *p;
	const char *pw_name = NULL, *gr_name = NULL;
	struct passwd pw;
	struct group group;
	string_t *errmsg;
	struct stat st;
	int orig_errno, ret, missing_mode = 0;

	orig_errno = errno;
	errmsg = t_str_new(256);
	str_printfa(errmsg, "%s(%s)", func, path);
	if (*path != '/') {
		if (t_get_current_dir(&dir) == 0) {
			str_printfa(errmsg, " in directory %s", dir);
			path = t_strconcat(dir, "/", path, NULL);
		}
	}
	str_printfa(errmsg, " failed: Permission denied (euid=%s",
		    dec2str(geteuid()));

	switch (i_getpwuid(geteuid(), &pw)) {
	case -1:
		str_append(errmsg, "(<getpwuid() error>)");
		break;
	case 0:
		str_append(errmsg, "(<unknown>)");
		break;
	default:
		pw_name = t_strdup(pw.pw_name);
		str_printfa(errmsg, "(%s)", pw_name);
		break;
	}

	str_printfa(errmsg, " egid=%s", dec2str(getegid()));
	switch (i_getgrgid(getegid(), &group)) {
	case -1:
		str_append(errmsg, "(<getgrgid() error>)");
		break;
	case 0:
		str_append(errmsg, "(<unknown>)");
		break;
	default:
		gr_name = t_strdup(group.gr_name);
		str_printfa(errmsg, "(%s)", gr_name);
		break;
	}

	prev_path = path; ret = -1;
	while (strcmp(prev_path, "/") != 0) {
		if ((p = strrchr(prev_path, '/')) == NULL)
			break;

		dir = t_strdup_until(prev_path, p);
		ret = stat(dir, &st);
		if (ret == 0)
			break;
		if (errno == EACCES && strcmp(dir, "/") != 0) {
			/* see if we have access to parent directory */
		} else if (errno == ENOENT && creating &&
			   strcmp(dir, "/") != 0) {
			/* probably mkdir_parents() failed here, find the first
			   parent directory we couldn't create */
		} else {
			/* some other error, can't handle it */
			str_printfa(errmsg, " stat(%s) failed: %m", dir);
			break;
		}
		prev_path = dir;
	}

	if (ret == 0) {
		/* dir is the first parent directory we can stat() */
		if (test_access(dir, X_OK, errmsg) < 0) {
			if (errno == EACCES)
				missing_mode = 1;
		} else if (creating && test_access(dir, W_OK, errmsg) < 0) {
			if (errno == EACCES)
				missing_mode = 2;
		} else if (prev_path == path &&
			   test_access(path, R_OK, errmsg) < 0) {
		} else if (!creating && test_access(path, W_OK, errmsg) < 0) {
			/* this produces a wrong error if the operation didn't
			   actually need write permissions, but we don't know
			   it here.. */
			if (errno == EACCES)
				missing_mode = 4;
		} else {
			str_append(errmsg, " UNIX perms appear ok "
				   "(ACL/MAC wrong?)");
		}
	}
	if (ret < 0)
		;
	else if (st.st_uid != geteuid()) {
		if (pw_name != NULL && i_getpwuid(st.st_uid, &pw) > 0 &&
		    strcmp(pw.pw_name, pw_name) == 0) {
			str_printfa(errmsg, ", conflicting dir uid=%s(%s)",
				    dec2str(st.st_uid), pw_name);
		} else {
			str_printfa(errmsg, ", dir owned by %s:%s mode=0%o",
				    dec2str(st.st_uid), dec2str(st.st_gid),
				    (unsigned int)(st.st_mode & 0777));
		}
	} else if (missing_mode != 0 &&
		   (((st.st_mode & 0700) >> 6) & missing_mode) == 0) {
		str_append(errmsg, ", dir owner missing perms");
	}
	if (ret == 0 && gr_name != NULL && st.st_gid != getegid()) {
		if (i_getgrgid(st.st_gid, &group) > 0 &&
		    strcmp(group.gr_name, gr_name) == 0) {
			str_printfa(errmsg, ", conflicting dir gid=%s(%s)",
				    dec2str(st.st_gid), gr_name);
		}
	}
	str_append_c(errmsg, ')');
	errno = orig_errno;
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

const char *eperm_error_get_chgrp(const char *func, const char *path,
				  gid_t gid, const char *gid_origin)
{
	string_t *errmsg;
	const struct group *group;
	int orig_errno = errno;

	errmsg = t_str_new(256);
	
	str_printfa(errmsg, "%s(%s, group=%s", func, path, dec2str(gid));
	group = getgrgid(gid);
	if (group != NULL)
		str_printfa(errmsg, "(%s)", group->gr_name);

	str_printfa(errmsg, ") failed: Operation not permitted (egid=%s",
		    dec2str(getegid()));
	group = getgrgid(getegid());
	if (group != NULL)
		str_printfa(errmsg, "(%s)", group->gr_name);
	if (gid_origin != NULL)
		str_printfa(errmsg, ", group based on %s", gid_origin);
	str_append(errmsg, " - see http://wiki2.dovecot.org/Errors/ChgrpNoPerm)");
	errno = orig_errno;
	return str_c(errmsg);
}
