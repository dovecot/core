/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "read-full.h"

#include <unistd.h>

int read_full(int fd, void *data, size_t size)
{
	ssize_t ret;

	while (size > 0) {
		ret = read(fd, data, size < SSIZE_T_MAX ? size : SSIZE_T_MAX);
		if (ret <= 0)
			return ret;

		data = PTR_OFFSET(data, ret);
		size -= ret;
	}

	return 1;
}

int pread_full(int fd, void *data, size_t size, off_t offset)
{
	ssize_t ret;

	while (size > 0) {
		ret = pread(fd, data, size < SSIZE_T_MAX ?
			    size : SSIZE_T_MAX, offset);
		if (ret <= 0)
			return ret;

		data = PTR_OFFSET(data, ret);
		size -= ret;
		offset += ret;
	}

	return 1;
}
