/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fdatasync-path.h"

#include <fcntl.h>
#include <unistd.h>

int fdatasync_path(const char *path)
{
	int fd, ret = 0;

	/* Directories need to be opened as read-only.
	   fsync() doesn't appear to care about it. */
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;
	if (fdatasync(fd) < 0) {
		/* Some OSes/FSes don't allow fsyncing directores. Silently
		   ignore the problem. */
		if (errno == EBADF) {
			/* e.g. NetBSD */
		} else if (errno == EINVAL) {
			/* e.g. Linux+CIFS */
		} else {
			ret = -1;
		}
	}
	(void)close(fd);
	return ret;
}
