/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef HAVE_POSIX_FALLOCATE
#  define _XOPEN_SOURCE 600 /* Required by glibc, breaks Solaris 9 */
#endif
#define _GNU_SOURCE /* for fallocate() */
#include "lib.h"
#include "file-set-size.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_LINUX_FALLOC_H
#  include <linux/falloc.h>
#endif

int file_set_size(int fd, off_t size)
{
#ifdef HAVE_POSIX_FALLOCATE
	static bool posix_fallocate_supported = TRUE;
#endif
	char block[IO_BLOCK_SIZE];
	off_t offset;
	ssize_t ret;
	struct stat st;

	i_assert(size >= 0);

	if (fstat(fd, &st) < 0) {
		i_error("fstat() failed: %m");
		return -1;
	}

	if (size < st.st_size) {
		if (ftruncate(fd, size) < 0) {
			i_error("ftruncate() failed: %m");
			return -1;
		}
		return 0;
	}
	if (size == st.st_size)
		return 0;

#ifdef HAVE_POSIX_FALLOCATE
	if (posix_fallocate_supported) {
		int err;

		err = posix_fallocate(fd, st.st_size, size - st.st_size);
		if (err == 0)
			return 0;

		if (err != EINVAL /* Solaris */ &&
		    err != EOPNOTSUPP /* AOX */) {
			if (!ENOSPACE(err))
				i_error("posix_fallocate() failed: %m");
			return -1;
		}
		/* Not supported by kernel, fallback to writing. */
		posix_fallocate_supported = FALSE;
	}
#endif
	/* start growing the file */
	offset = st.st_size;
	memset(block, 0, I_MIN((ssize_t)sizeof(block), size - offset));

	while (offset < size) {
		ret = pwrite(fd, block,
			     I_MIN((ssize_t)sizeof(block), size - offset),
			     offset);
		if (ret < 0) {
			if (!ENOSPACE(errno))
				i_error("pwrite() failed: %m");
			return -1;
		}
		offset += ret;
	}
	return 0;
}

int file_preallocate(int fd ATTR_UNUSED, off_t size ATTR_UNUSED)
{
#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_KEEP_SIZE)
	/* Linux */
	if (fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, size) < 0)
		return errno == ENOSYS ? 0 : -1;
	return 1;
#else
	return 0;
#endif
}
