/*
 mmap-util.c - Memory mapping utilities

    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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
