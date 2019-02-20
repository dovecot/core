/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

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
#include "path-util.h"
#include "unlink-directory.h"

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define ERROR_FORMAT "%s(%s) failed: %m"
#define ERROR_FORMAT_DNAME "%s(%s/%s) failed: %m"

static void ATTR_FORMAT(3,4)
unlink_directory_error(const char **error,
		       int *first_errno,
		       const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	const char *err = t_strdup_vprintf(fmt, args);
	if (*error == NULL) {
		if (first_errno != NULL)
			*first_errno = errno;
		*error = err;
	} else
		i_error("%s", err);
	va_end(args);
}

static int
unlink_directory_r(const char *dir, enum unlink_directory_flags flags,
		   const char **error)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
        int dir_fd, old_errno;

#ifdef O_NOFOLLOW
	dir_fd = open(dir, O_RDONLY | O_NOFOLLOW);
	if (dir_fd == -1) {
		unlink_directory_error(error, NULL,
				       "open(%s, O_RDONLY | O_NOFOLLOW) failed: %m",
				       dir);
		return -1;
	}
#else
	struct stat st2;

	if (lstat(dir, &st) < 0) {
		unlink_directory_error(error_r, NULL, ERROR_FORMAT, "lstat", dir);
		return -1;
	}

	if (!S_ISDIR(st.st_mode)) {
		if ((st.st_mode & S_IFMT) != S_IFLNK) {
			unlink_directory_error(error_r, NULL, "%s is not a directory: %s", dir);
			errno = ENOTDIR;
		} else {
			/* be compatible with O_NOFOLLOW */
			errno = ELOOP;
			unlink_directory_error(error_r, NULL, "%s is a symlink, not a directory: %s", dir);
		}
		return -1;
	}

	dir_fd = open(dir, O_RDONLY);
	if (dir_fd == -1) {
		unlink_directory_error(error_r, NULL, "open(%s, O_RDONLY) failed: %m", dir);
		return -1;
	}

	if (fstat(dir_fd, &st2) < 0) {
		i_close_fd(&dir_fd);
		unlink_directory_error(error_r, NULL, ERROR_FORMAT, "fstat", dir);
		return -1;
	}

	if (st.st_ino != st2.st_ino ||
	    !CMP_DEV_T(st.st_dev, st2.st_dev)) {
		/* directory was just replaced with something else. */
		i_close_fd(&dir_fd);
		errno = ENOTDIR;
		unlink_directory_error(error_r, NULL, "%s race condition: directory was just replaced", dir);
		return -1;
	}
#endif
	if (fchdir(dir_fd) < 0) {
                i_close_fd(&dir_fd);
		unlink_directory_error(error, NULL, ERROR_FORMAT, "fchdir", dir);
		return -1;
	}

	dirp = opendir(".");
	if (dirp == NULL) {
		i_close_fd(&dir_fd);
		unlink_directory_error(error, NULL, "opendir(.) (in %s) failed: %m", dir);
		return -1;
	}

	int first_errno = 0;
	for (;;) {
		errno = 0;
		d = readdir(dirp);
		if (d == NULL) {
			if (errno != 0) {
				unlink_directory_error(error,
						       &first_errno,
						       ERROR_FORMAT,
						       "readdir",
						       dir);
			}
			break;
		}
		if (d->d_name[0] == '.') {
			if ((d->d_name[1] == '\0' ||
			     (d->d_name[1] == '.' && d->d_name[2] == '\0'))) {
				/* skip . and .. */
				continue;
			}
			if ((flags & UNLINK_DIRECTORY_FLAG_SKIP_DOTFILES) != 0)
				continue;
		}

		if (unlink(d->d_name) < 0 && errno != ENOENT) {
			old_errno = errno;

			if (lstat(d->d_name, &st) < 0) {
				if (errno != ENOENT) {
					unlink_directory_error(error,
							       &first_errno,
							       ERROR_FORMAT,
							       "lstat",
							       dir);
					break;
				}
			} else if (S_ISDIR(st.st_mode) &&
				   (flags & UNLINK_DIRECTORY_FLAG_FILES_ONLY) == 0) {
				if (unlink_directory_r(d->d_name, flags, error) < 0) {
					if (first_errno == 0)
						first_errno = errno;
					if (errno != ENOENT)
						break;
				}
				if (fchdir(dir_fd) < 0) {
					unlink_directory_error(error,
							       &first_errno,
							       ERROR_FORMAT,
							       "fchdir",
							       dir);
					break;
				}

				if (rmdir(d->d_name) < 0 &&
				    errno != ENOENT) {
					if (errno == EEXIST)
						/* standardize errno */
						errno = ENOTEMPTY;
					unlink_directory_error(error,
							       &first_errno,
							       ERROR_FORMAT,
							       "rmdir",
							       dir);
					break;
				}
			} else if (S_ISDIR(st.st_mode) &&
				   (flags & UNLINK_DIRECTORY_FLAG_FILES_ONLY) != 0) {
				/* skip directory */
			} else if (old_errno == EBUSY &&
				   str_begins(d->d_name, ".nfs")) {
				/* can't delete NFS files that are still
				   in use. let the caller decide if this error
				   is worth logging about */
				break;
			} else
                                /* so it wasn't a directory */
				unlink_directory_error(error,
						       &first_errno,
						       ERROR_FORMAT_DNAME,
						       "unlink",
						       dir,
						       d->d_name);
		}
	}

	i_close_fd(&dir_fd);
	if (closedir(dirp) < 0)
		unlink_directory_error(error,
				       &first_errno,
				       ERROR_FORMAT,
				       "closedir",
				       dir);

	if (*error != NULL) {
		errno = first_errno;
		return -1;
	}
	return 0;
}

int unlink_directory(const char *dir, enum unlink_directory_flags flags,
		     const char **error_r)
{
	const char *orig_dir, *error;
	int fd, ret, old_errno;

	if (t_get_working_dir(&orig_dir, &error) < 0) {
		i_warning("Could not get working directory in unlink_directory(): %s",
			  error);
		orig_dir = ".";
	}

	fd = open(".", O_RDONLY);
	if (fd == -1) {
		*error_r = t_strdup_printf(
			"Can't preserve current directory %s: "
			"open(.) failed: %m", orig_dir);
		return -1;
	}

	/* Cannot set error_r to NULL inside of unlink_directory_r()
	   because of recursion */
	*error_r = NULL;
	ret = unlink_directory_r(dir, flags, error_r);
	old_errno = errno;

	if (fchdir(fd) < 0) {
		i_fatal("unlink_directory(%s): "
			"Can't fchdir() back to our original dir %s: %m", dir, orig_dir);
	}
	i_close_fd(&fd);

	if (ret < 0) {
		errno = old_errno;
		return errno == ENOENT ? 0 : -1;
	}

	if ((flags & UNLINK_DIRECTORY_FLAG_RMDIR) != 0) {
		if (rmdir(dir) < 0 && errno != ENOENT) {
			*error_r = t_strdup_printf("rmdir(%s) failed: %m", dir);
			if (errno == EEXIST) {
				/* standardize errno */
				errno = ENOTEMPTY;
			}
			return errno == ENOENT ? 0 : 1;
		}
	}
	return 1;
}
