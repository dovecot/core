/*
 file-set-size.c - portable way to grow/shrink file size

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
#include "write-full.h"
#include "file-set-size.h"

#include <unistd.h>

int file_set_size(int fd, off_t size)
{
	char block[1024];
	off_t pos;

	i_assert(size >= 0);

	pos = lseek(fd, 0, SEEK_END);
	if (pos < 0)
		return -1;

	if (size < pos)
		return ftruncate(fd, size);
	if (size == pos)
		return 0;

	/* start growing the file */
	memset(block, 0, sizeof(block));

	size -= pos;
	while ((uoff_t)size > sizeof(block)) {
		/* write in 1kb blocks */
		if (write_full(fd, block, sizeof(block)) < 0)
			return -1;
		size -= sizeof(block);
	}

	/* write the remainder */
	return write_full(fd, block, (size_t)size) < 0 ? -1 : 0;
}
