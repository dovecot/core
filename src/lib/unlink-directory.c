/*
 unlink-directory.c : Unlink directory with everything under it.

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
#include "unlink-directory.h"

#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

int unlink_directory(const char *dir, int unlink_dir)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
	char path[PATH_MAX];

	dirp = opendir(dir);
	if (dirp == NULL)
		return errno == ENOENT ? 0 : -1;

	while ((d = readdir(dirp)) != NULL) {
		if (d->d_name[0] == '.' &&
		    (d->d_name[1] == '\0' ||
		     (d->d_name[1] == '.' && d->d_name[2] == '\0'))) {
			/* skip . and .. */
			continue;
		}

		if (str_path(path, sizeof(path), dir, d->d_name) < 0)
			return -1;

		if (unlink(path) == -1 && errno != ENOENT) {
			int old_errno = errno;

			if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
				if (unlink_directory(path, TRUE) < 0)
					return -1;
			} else {
				/* so it wasn't a directory, unlink() again
				   to get correct errno */
				errno = old_errno;
				return -1;
			}
		}
	}

	if (closedir(dirp) < 0)
		return -1;

	if (unlink_dir) {
		if (rmdir(dir) == -1 && errno != ENOENT)
			return -1;
	}

	return 0;
}
