/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "safe-mkdir.h"

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int safe_mkdir(const char *dir, mode_t mode, uid_t uid, gid_t gid)
{
	struct stat st;
	int fd, ret = 2, changed_ret = 0;

	if (lstat(dir, &st) < 0) {
		if (errno != ENOENT)
			i_fatal("lstat() failed for %s: %m", dir);

		if (mkdir(dir, mode) < 0) {
			if (errno != EEXIST)
				i_fatal("Can't create directory %s: %m", dir);
		} else {
			/* created it */
			ret = changed_ret = 1;
		}
	}

	/* use fchown() and fchmod() just to make sure we aren't following
	   symbolic links. */
	fd = open(dir, O_RDONLY);
	if (fd == -1)
		i_fatal("open() failed for %s: %m", dir);

	if (fstat(fd, &st) < 0)
		i_fatal("fstat() failed for %s: %m", dir);

	if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
		i_fatal("Not a directory %s", dir);

	/* change the file owner first, since it's the only user one who
	   can mess up with the file mode. */
	if ((st.st_uid != uid && uid != (uid_t)-1) ||
	    (st.st_gid != gid && gid != (gid_t)-1)) {
		if (fchown(fd, uid, gid) < 0)
			i_fatal("fchown() failed for %s: %m", dir);
		ret = changed_ret;
	}

	if ((st.st_mode & 07777) != mode) {
		if (fchmod(fd, mode) < 0)
			i_fatal("chmod() failed for %s: %m", dir);
		ret = changed_ret;
	}

	if (close(fd) < 0)
		i_fatal("close() failed for %s: %m", dir);

	/* paranoia: make sure we succeeded in everything. */
	if (lstat(dir, &st) < 0)
		i_fatal("lstat() check failed for %s: %m", dir);

	if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
		i_fatal("Not a directory %s", dir);

	if ((st.st_mode & 07777) != mode) {
		i_fatal("safe_mkdir() failed: %s (%o) is still not mode %o",
			dir, (int)st.st_mode, (int)mode);
	}
	if ((st.st_uid != uid && uid != (uid_t)-1) ||
	    (st.st_gid != gid && gid != (gid_t)-1)) {
		i_fatal("safe_mkdir() failed: %s (%s, %s) "
			"is still not owned by %s.%s",
			dir, dec2str(st.st_uid), dec2str(st.st_gid),
			dec2str(uid), dec2str(gid));
	}

	return ret;
}
