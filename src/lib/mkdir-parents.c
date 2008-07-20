/* Copyright (c) 2003-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mkdir-parents.h"

#include <sys/stat.h>
#include <unistd.h>

static int mkdir_chown(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	mode_t old_mask;
	int ret;

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
		i_error("chown(%s, %ld, %ld) failed: %m", path,
			uid == (uid_t)-1 ? -1L : (long)uid,
			gid == (gid_t)-1 ? -1L : (long)gid);
		return -1;
	}
	return 0;
}

int mkdir_parents_chown(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	const char *p;
	int ret;

	if (mkdir_chown(path, mode, uid, gid) < 0) {
		if (errno != ENOENT)
			return -1;

		/* doesn't exist, try recursively creating our parent dir */
		p = strrchr(path, '/');
		if (p == NULL || p == path)
			return -1; /* shouldn't happen */

		T_BEGIN {
			ret = mkdir_parents_chown(t_strdup_until(path, p),
						  mode, uid, gid);
		} T_END;
		if (ret < 0)
			return -1;

		/* should work now */
		if (mkdir_chown(path, mode, uid, gid) < 0)
			return -1;
	}
	return 0;
}

int mkdir_parents(const char *path, mode_t mode)
{
	return mkdir_parents_chown(path, mode, (uid_t)-1, (gid_t)-1);
}
