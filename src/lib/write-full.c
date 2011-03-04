/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "write-full.h"

#include <unistd.h>

int write_full(int fd, const void *data, size_t size)
{
	ssize_t ret;

	while (size > 0) {
		ret = write(fd, data, size < SSIZE_T_MAX ? size : SSIZE_T_MAX);
		if (unlikely(ret < 0))
			return -1;

		if (unlikely(ret == 0)) {
			/* nothing was written, only reason for this should
			   be out of disk space */
			errno = ENOSPC;
			return -1;
		}

		data = CONST_PTR_OFFSET(data, ret);
		size -= ret;
	}

	return 0;
}

int pwrite_full(int fd, const void *data, size_t size, off_t offset)
{
	ssize_t ret;

	while (size > 0) {
		ret = pwrite(fd, data, size < SSIZE_T_MAX ?
			     size : SSIZE_T_MAX, offset);
		if (unlikely(ret < 0))
			return -1;

		if (unlikely(ret == 0)) {
			/* nothing was written, only reason for this should
			   be out of disk space */
			errno = ENOSPC;
			return -1;
		}

		data = CONST_PTR_OFFSET(data, ret);
		size -= ret;
		offset += ret;
	}

	return 0;
}
