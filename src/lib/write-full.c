/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "write-full.h"

#include <unistd.h>

int write_full(int fd, const void *data, size_t size)
{
	ssize_t ret;

	while (size > 0) {
		ret = write(fd, data, size < SSIZE_T_MAX ? size : SSIZE_T_MAX);
		if (ret < 0)
			return -1;

		if (ret == 0) {
			/* nothing was written, only reason for this should
			   be out of disk space */
			errno = ENOSPC;
			return -1;
		}
		size -= ret;
	}

	return 0;
}
