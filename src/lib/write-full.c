/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "write-full.h"

#include <unistd.h>

int write_full(int fd, const void *data, size_t size)
{
	size_t written;
	if (write_full_count(fd, data, size, &written) < 0)
		return -1;
	i_assert(written == size);
	return 0;
}

int write_full_count(int fd, const void *data, size_t size, size_t *written_r)
{
	size_t pos = 0;
	ssize_t ret;

	i_assert(size <= SSIZE_T_MAX);

	while (pos < size) {
		ret = write(fd, CONST_PTR_OFFSET(data, pos), size - pos);
		if (unlikely(ret < 0))
			break;

		if (unlikely(ret == 0)) {
			/* nothing was written, only reason for this should
			   be out of disk space */
			errno = ENOSPC;
			break;
		}

		pos += ret;
	}

	*written_r = pos;
	return pos == size ? 0 : -1;
}

int pwrite_full(int fd, const void *data, size_t size, off_t offset)
{
	ssize_t ret;

	i_assert(size <= SSIZE_T_MAX);

	while (size > 0) {
		ret = pwrite(fd, data, size, offset);
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
