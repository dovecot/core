/*
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
#include "safe-mkdir.h"

#include <sys/stat.h>
#include <unistd.h>

int safe_mkdir(const char *dir, mode_t mode, uid_t uid, gid_t gid)
{
	struct stat st;
	int ret = 1;

	if (lstat(dir, &st) < 0) {
		if (errno != ENOENT)
			i_fatal("lstat() failed for %s: %m", dir);

		if (mkdir(dir, mode) < 0)
			i_fatal("Can't create directory %s: %m", dir);

		if (lchown(dir, uid, gid) < 0)
			i_fatal("lchown() failed for %s: %m", dir);
	} else {
		/* make sure it's permissions are correct */
		if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
			i_fatal("Not a directory %s", dir);

		if (st.st_uid != uid || st.st_gid != gid) {
			if (lchown(dir, uid, gid) < 0)
				i_fatal("lchown() failed for %s: %m", dir);
			ret = 0;
		}

		if ((st.st_mode & 07777) != mode) {
			if (chmod(dir, mode) < 0)
				i_fatal("chmod() failed for %s: %m", dir);
			ret = 0;
		}
	}

	/* make sure we succeeded in everything. chown() and chmod()
	   are racy: user owned 0777 file - change either and the user
	   can still change it back. */
	if (lstat(dir, &st) < 0)
		i_fatal("lstat() check failed for %s: %m", dir);

	if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
		i_fatal("safe_mkdir() failed: %s is still not a directory",
			dir);
	}

	if ((st.st_mode & 07777) != mode) {
		i_fatal("safe_mkdir() failed: %s (%o) is still not mode %o",
			dir, (int)st.st_mode, (int)mode);
	}
	if (st.st_uid != uid || st.st_gid != gid) {
		i_fatal("safe_mkdir() failed: %s (%s, %s) "
			"is still not owned by %s.%s",
			dir, dec2str(st.st_uid), dec2str(st.st_gid),
			dec2str(uid), dec2str(gid));
	}

	return ret;
}
