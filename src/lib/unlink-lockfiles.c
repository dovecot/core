/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "unlink-lockfiles.h"

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

int unlink_lockfiles(const char *dir, const char *pidprefix,
		     const char *otherprefix, time_t other_min_time)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
	string_t *path;
	unsigned int pidlen, otherlen;
	int ret = 1;

	/* check for any invalid access files */
	dirp = opendir(dir);
	if (dirp == NULL)
		return -1;

	t_push();
	path = t_str_new(512);
	pidlen = pidprefix == NULL ? 0 : strlen(pidprefix);
	otherlen = otherprefix == NULL ? 0 : strlen(otherprefix);

	while ((d = readdir(dirp)) != NULL) {
		const char *fname = d->d_name;

		if (pidprefix != NULL &&
		    strncmp(fname, pidprefix, pidlen) == 0 &&
		    is_numeric(fname+pidlen, '\0')) {
			/* found a lock file from our host - see if the PID
			   is valid (meaning it exists, and the it's with
			   the same UID as us) */
			if (kill(atol(fname+pidlen), 0) == 0 || errno != ESRCH)
				continue; /* valid */

			str_truncate(path, 0);
			str_printfa(path, "%s/%s", dir, fname);
			if (unlink(str_c(path)) < 0 && errno != ENOENT) {
				i_error("unlink(%s) failed: %m", str_c(path));
				ret = 0;
			}
		} else if (otherprefix != NULL &&
			   strncmp(fname, otherprefix, otherlen) == 0) {
			str_truncate(path, 0);
			str_printfa(path, "%s/%s", dir, fname);
			if (stat(str_c(path), &st) == 0 &&
			    st.st_mtime < other_min_time &&
			    st.st_ctime < other_min_time)
				if (unlink(str_c(path)) < 0 &&
				    errno != ENOENT) {
					i_error("unlink(%s) failed: %m",
						str_c(path));
					ret = 0;
				}
		}
	}

	if (closedir(dirp) < 0)
		i_error("closedir(%s) failed: %m", dir);

	t_pop();
	return ret;
}
