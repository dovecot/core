/*
 unlink-lockfiles.c : Utility function for easier deletion of lock files.

    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "unlink-lockfiles.h"

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

void unlink_lockfiles(const char *dir, const char *pidprefix,
		      const char *otherprefix, time_t other_min_time)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
	char path[1024];
	unsigned int pidlen, otherlen;

	/* check for any invalid access files */
	dirp = opendir(dir);
	if (dirp == NULL)
		return;

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
			if (kill(atoi(fname+pidlen), 0) == 0)
				continue; /* valid */

			i_snprintf(path, sizeof(path), "%s/%s", dir, fname);
			(void)unlink(path);
		} else if (otherprefix != 0 &&
			   strncmp(fname, otherprefix, otherlen) == 0) {
			i_snprintf(path, sizeof(path), "%s/%s", dir, fname);
			if (stat(path, &st) == 0 &&
			    st.st_mtime < other_min_time) {
				(void)unlink(path);
			}
		}
	}

	(void)closedir(dirp);
}
