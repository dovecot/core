/* Copyright (c) 1999-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fd-set-nonblock.h"

#include <fcntl.h>

int fd_set_nonblock(int fd, bool nonblock)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		i_error("fcntl(%d, F_GETFL) failed: %m", fd);
		return -1;
	}

	if (nonblock)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) < 0) {
		i_error("fcntl(%d, F_SETFL) failed: %m", fd);
		return -1;
	}
	return 0;
}
