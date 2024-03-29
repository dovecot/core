/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mmap-util.h"

#include <sys/stat.h>

void *mmap_file(int fd, size_t *length, int prot)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return MAP_FAILED;

#if OFF_T_MAX > SSIZE_T_MAX
	if (st.st_size > SSIZE_T_MAX) {
		/* too large file to map into memory */
		errno = EFBIG;
		return MAP_FAILED;
	}
#endif

	*length = (size_t)st.st_size;
	if (*length == 0)
		return NULL;

	i_assert(*length > 0 && *length < SSIZE_T_MAX);

	return mmap(NULL, *length, prot, MAP_SHARED, fd, 0);
}

void *mmap_ro_file(int fd, size_t *length)
{
	return mmap_file(fd, length, PROT_READ);
}

void *mmap_rw_file(int fd, size_t *length)
{
	return mmap_file(fd, length, PROT_READ | PROT_WRITE);
}

size_t mmap_get_page_size(void)
{
	static size_t size = 0;

	if (size != 0)
		return size;
	long ret = sysconf(_SC_PAGESIZE);
	i_assert(ret > 0);
	i_assert(ret <= SSIZE_T_MAX);
	size = (size_t)ret;
	return size;
}
