/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/*
   There's a bit tricky race condition with recursive deletion.
   Suppose this happens:

   lstat(dir, ..) -> OK, it's a directory
   // attacker deletes dir, replaces it with symlink to /
   opendir(dir) -> it actually opens /

   Most portable solution is to lstat() the dir, chdir() there, then check
   that "." points to same device/inode as we originally lstat()ed. This
   assumes that the device has usable inodes, most should except for some NFS
   implementations.

   Filesystems may also reassign a deleted inode to another file
   immediately after it's deleted. That in theory makes it possible to exploit
   this race to delete the new directory. However, the new inode is quite
   unlikely to be any important directory, and attacker is quite unlikely to
   find out which directory even got the inode. Maybe with some setuid program
   or daemon interaction something could come out of it though.

   Another less portable solution is to fchdir(open(dir, O_NOFOLLOW)).
   This should be completely safe.

   The actual file deletion also has to be done relative to current
   directory, to make sure that the whole directory structure isn't replaced
   with another one while we're deleting it. Going back to parent directory
   isn't too easy either - safest (and easiest) way again is to open() the
   directory and fchdir() back there.
*/

#define _GNU_SOURCE /* for O_NOFOLLOW with Linux */

#include "lib.h"
#include "close-keep-errno.h"
#include "unlink-directory.h"

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

static int unlink_directory_r(const char *dir)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
        int dir_fd, old_errno;

#ifdef O_NOFOLLOW
	dir_fd = open(dir, O_RDONLY | O_NOFOLLOW);
	if (dir_fd == -1)
		return -1;
#else
	struct stat st2;

	if (lstat(dir, &st) < 0)
		return -1;

	if (!S_ISDIR(st.st_mode)) {
		if ((st.st_mode & S_IFMT) != S_IFLNK)
			errno = ENOTDIR;
		else {
			/* be compatible with O_NOFOLLOW */
			errno = ELOOP;
		}
		return -1;
	}

	dir_fd = open(dir, O_RDONLY);
	if (dir_fd == -1)
		return -1;

	if (fstat(dir_fd, &st2) < 0) {
		close_keep_errno(dir_fd);
		return -1;
	}

	if (st.st_ino != st2.st_ino ||
	    !CMP_DEV_T(st.st_dev, st2.st_dev)) {
		/* directory was just replaced with something else. */
		(void)close(dir_fd);
		errno = ENOTDIR;
		return -1;
	}
#endif
	if (fchdir(dir_fd) < 0) {
                close_keep_errno(dir_fd);
		return -1;
	}

	dirp = opendir(".");
	if (dirp == NULL) {
		close_keep_errno(dir_fd);
		return -1;
	}

	errno = 0;
	while ((d = readdir(dirp)) != NULL) {
		if (d->d_name[0] == '.' &&
		    (d->d_name[1] == '\0' ||
		     (d->d_name[1] == '.' && d->d_name[2] == '\0'))) {
			/* skip . and .. */
			continue;
		}

		if (unlink(d->d_name) < 0 && errno != ENOENT) {
			old_errno = errno;

			if (lstat(d->d_name, &st) < 0) {
				if (errno != ENOENT)
					break;
				errno = 0;
			} else if (S_ISDIR(st.st_mode)) {
				if (unlink_directory_r(d->d_name) < 0) {
					if (errno != ENOENT)
						break;
					errno = 0;
				}
				if (fchdir(dir_fd) < 0)
					break;

				if (rmdir(d->d_name) < 0) {
					if (errno != ENOENT) {
						if (errno == EEXIST) {
							/* standardize errno */
							errno = ENOTEMPTY;
						}
						break;
					}
					errno = 0;
				}
			} else if (old_errno == EBUSY &&
				   strncmp(d->d_name, ".nfs", 4) == 0) {
				/* can't delete NFS files that are still
				   in use. let the caller decide if this error
				   is worth logging about */
				break;
			} else {
                                /* so it wasn't a directory */
				errno = old_errno;
				i_error("unlink(%s/%s) failed: %m",
					dir, d->d_name);
				break;
			}
		}
	}
	old_errno = errno;

	(void)close(dir_fd);
	if (closedir(dirp) < 0)
		return -1;

	if (old_errno != 0) {
		errno = old_errno;
		return -1;
	}

	return 0;
}

int unlink_directory(const char *dir, bool unlink_dir)
{
	int fd, ret, old_errno;

	fd = open(".", O_RDONLY);
	if (fd == -1)
		return -1;

	ret = unlink_directory_r(dir);
	if (ret < 0 && errno == ENOENT)
		ret = 0;
	old_errno = errno;

	if (fchdir(fd) < 0) {
		i_fatal("unlink_directory(%s): "
			"Can't fchdir() back to our original dir: %m", dir);
	}
	(void)close(fd);

	if (ret < 0) {
		errno = old_errno;
		return -1;
	}

	if (unlink_dir) {
		if (rmdir(dir) < 0 && errno != ENOENT) {
			if (errno == EEXIST) {
				/* standardize errno */
				errno = ENOTEMPTY;
			}
			return -1;
		}
	}

	return 0;
}
