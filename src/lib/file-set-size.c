/* Copyright (c) 2002-2003 Timo Sirainen */

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
