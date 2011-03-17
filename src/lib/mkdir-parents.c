/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "eacces-error.h"
#include "mkdir-parents.h"
#include "ipwd.h"

#include <sys/stat.h>
#include <unistd.h>

static int
mkdir_chown_full(const char *path, mode_t mode, uid_t uid,
		 gid_t gid, const char *gid_origin)
{
	string_t *str;
	mode_t old_mask;
	int ret, orig_errno;

	old_mask = umask(0);
	ret = mkdir(path, mode);
	umask(old_mask);

	if (ret < 0) {
		if (errno == EISDIR || errno == ENOSYS) {
			/* EISDIR check is for BSD/OS which returns it if path
			   contains '/' at the end and it exists.

			   ENOSYS check is for NFS mount points. */
			errno = EEXIST;
		}
		return -1;
	}
	if (chown(path, uid, gid) < 0) {
		orig_errno = errno;
		if (rmdir(path) < 0)
			i_error("rmdir(%s) failed: %m", path);
		errno = orig_errno;

		if (errno == EPERM && uid == (uid_t)-1) {
			i_error("%s", eperm_error_get_chgrp("chown", path, gid,
							    gid_origin));
			return -1;
		}

		str = t_str_new(256);
		str_printfa(str, "chown(%s, %ld", path,
			    uid == (uid_t)-1 ? -1L : (long)uid);
		if (uid != (uid_t)-1) {
			struct passwd pw;

			if (i_getpwuid(uid, &pw) > 0)
				str_printfa(str, "(%s)", pw.pw_name);

		}
		str_printfa(str, ", %ld",
			    gid == (gid_t)-1 ? -1L : (long)gid);
		if (gid != (gid_t)-1) {
			struct group gr;

			if (i_getgrgid(uid, &gr) > 0)
				str_printfa(str, "(%s)", gr.gr_name);
		}
		errno = orig_errno;
		i_error("%s) failed: %m", str_c(str));
		return -1;
	}
	return 0;
}

int mkdir_chown(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return mkdir_chown_full(path, mode, uid, gid, NULL);
}

int mkdir_chgrp(const char *path, mode_t mode,
		gid_t gid, const char *gid_origin)
{
	return mkdir_chown_full(path, mode, (uid_t)-1, gid, gid_origin);
}

static int
mkdir_parents_chown_full(const char *path, mode_t mode, uid_t uid, gid_t gid,
			 const char *gid_origin)
{
	const char *p;
	int ret;

	if (mkdir_chown_full(path, mode, uid, gid, gid_origin) < 0) {
		if (errno != ENOENT)
			return -1;

		/* doesn't exist, try recursively creating our parent dir */
		p = strrchr(path, '/');
		if (p == NULL || p == path)
			return -1; /* shouldn't happen */

		T_BEGIN {
			ret = mkdir_parents_chown_full(t_strdup_until(path, p),
						       mode, uid,
						       gid, gid_origin);
		} T_END;
		if (ret < 0)
			return -1;

		/* should work now */
		if (mkdir_chown_full(path, mode, uid, gid, gid_origin) < 0)
			return -1;
	}
	return 0;
}

int mkdir_parents_chown(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return mkdir_parents_chown_full(path, mode, uid, gid, NULL);
}

int mkdir_parents_chgrp(const char *path, mode_t mode,
			gid_t gid, const char *gid_origin)
{
	return mkdir_parents_chown_full(path, mode, (uid_t)-1, gid, gid_origin);
}

int mkdir_parents(const char *path, mode_t mode)
{
	return mkdir_parents_chown(path, mode, (uid_t)-1, (gid_t)-1);
}
