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

static void *mmap_file(int fd, size_t *length, int access)
{
	*length = lseek(fd, 0, SEEK_END);
	if ((off_t)*length == (off_t)-1)
		return MAP_FAILED;

	if (*length == 0)
		return NULL;

	i_assert(*length > 0 && *length < INT_MAX);

	return mmap(NULL, *length, access, MAP_SHARED, fd, 0);
}

void *mmap_ro_file(int fd, size_t *length)
{
	return mmap_file(fd, length, PROT_READ);
}

void *mmap_rw_file(int fd, size_t *length)
{
	return mmap_file(fd, length, PROT_READ | PROT_WRITE);
}

void *mmap_aligned(int fd, int access, off_t offset, size_t length,
		   void **data_start, size_t *mmap_length)
{
	void *mmap_base;

#ifdef HAVE_GETPAGESIZE
	static int pagemask = 0;

	if (pagemask == 0) {
		pagemask = getpagesize();
		i_assert(pagemask > 0);
		pagemask--;
	}

	*mmap_length = length + (offset & pagemask);

	mmap_base = mmap(NULL, *mmap_length, access, MAP_SHARED,
			 fd, offset & ~pagemask);
	*data_start = mmap_base == MAP_FAILED || mmap_base == NULL ? NULL :
		(char *) mmap_base + (offset & pagemask);
#else
	*mmap_length = length + offset;

	mmap_base = mmap(NULL, *mmap_length, access, MAP_SHARED, fd, 0);
	*data_start = mmap_base == MAP_FAILED || mmap_base == NULL ? NULL :
		(char *) mmap_base + offset;
#endif

	return mmap_base;
}

#ifndef HAVE_MADVISE
int madvise(void *start, size_t length, int advice)
{
}
#endif
