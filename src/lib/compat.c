/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "config.h"
#undef HAVE_CONFIG_H

#define IN_COMPAT_C
#include "lib.h"

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>


#if !defined(HAVE_PREAD)
ssize_t i_my_pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t ret;
	off_t old_offset;

	old_offset = lseek(fd, 0, SEEK_CUR);
	if (old_offset == -1)
		return -1;

	if (lseek(fd, offset, SEEK_SET) < 0)
		return -1;

	ret = read(fd, buf, count);
	if (ret < 0)
		return -1;

	if (lseek(fd, old_offset, SEEK_SET) < 0)
		return -1;
	return ret;
}

ssize_t i_my_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	ssize_t ret;
	off_t old_offset;

	old_offset = lseek(fd, 0, SEEK_CUR);
	if (old_offset == -1)
		return -1;

	if (lseek(fd, offset, SEEK_SET) < 0)
		return -1;

	ret = write(fd, buf, count);
	if (ret < 0)
		return -1;

	if (lseek(fd, old_offset, SEEK_SET) < 0)
		return -1;
	return ret;
}
#elif defined(PREAD_WRAPPERS)

ssize_t i_my_pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t ret;

	ret = pread(fd, buf, count, offset);
	return ret;
}

ssize_t i_my_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	return pwrite(fd, buf, count, offset);
}
#endif
