/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"

#include <sys/stat.h>

void *mmap_file(int fd, size_t *length, int prot)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return MAP_FAILED;

	if (st.st_size > SSIZE_T_MAX) {
		/* too large file to map into memory */
		errno = EFBIG;
		return MAP_FAILED;
	}

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

#ifndef HAVE_MADVISE
int madvise(void *start __attr_unused__, size_t length __attr_unused__,
	    int advice __attr_unused__)
{
}
#endif
