/* Copyright (c) 2006 Timo Sirainen */

#include "lib.h"
#include "close-keep-errno.h"

#include <unistd.h>

void close_keep_errno(int fd)
{
	int old_errno = errno;
	(void)close(fd);
	errno = old_errno;
}
