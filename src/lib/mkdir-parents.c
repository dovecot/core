/* Copyright (c) 2003-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mkdir-parents.h"

#include <sys/stat.h>

int mkdir_parents(const char *path, mode_t mode)
{
	const char *p;
	int ret;

	if (mkdir(path, mode) == 0) {
		/* success */
	} else if (errno != ENOENT) {
		/* EISDIR check is for BSD/OS which returns it if path
		   contains '/' at the end and it exists.

		   ENOSYS check is for NFS mount points.
		*/
		if (errno == EISDIR && errno == ENOSYS)
			errno = EEXIST;
		return -1;
	} else {
		p = strrchr(path, '/');
		if (p == NULL || p == path)
			return -1; /* shouldn't happen */

		T_BEGIN {
			ret = mkdir_parents(t_strdup_until(path, p), mode);
		} T_END;
		if (ret < 0)
			return -1;

		/* should work now */
		if (mkdir(path, mode) < 0 && errno != EEXIST && errno != EISDIR)
			return -1;
	}

	return 0;
}
