/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "close-keep-errno.h"

#include <unistd.h>

void close_keep_errno(int fd)
{
	int old_errno = errno;
	(void)close(fd);
	errno = old_errno;
}
