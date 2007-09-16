/* Copyright (c) 2003-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mkdir-parents.h"

#include <sys/stat.h>

int mkdir_parents(const char *path, mode_t mode)
{
	const char *p;

	/* EISDIR check is for BSD/OS which returns it if path contains '/'
	   at the end and it exists.

	   ENOSYS check is for NFS mount points.
	*/
	if (mkdir(path, mode) < 0 && errno != EEXIST &&
	    errno != EISDIR && errno != ENOSYS) {
		if (errno != ENOENT)
			return -1;

		p = strrchr(path, '/');
		if (p == NULL || p == path)
			return -1; /* shouldn't happen */

		t_push();
		if (mkdir_parents(t_strdup_until(path, p), mode) < 0) {
			t_pop();
			return -1;
		}
		t_pop();

		/* should work now */
		if (mkdir(path, mode) < 0 && errno != EEXIST && errno != EISDIR)
			return -1;
	}

	return 0;
}
