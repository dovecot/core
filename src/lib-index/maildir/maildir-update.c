/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "maildir-index.h"
#include "mail-index-util.h"

int maildir_record_update(MailIndex *index, MailIndexUpdate *update,
			  int fd, const char *path)
{
	void *mmap_base;
	size_t mmap_length;

	i_assert(path != NULL);

	/* we need only the header which probably fits into one page,
	   so don't use MADV_SEQUENTIAL which would just read more than
	   is needed. */
	mmap_base = mmap_ro_file(fd, &mmap_length);
	if (mmap_base == MAP_FAILED) {
		index_set_error(index, "update: mmap() failed with file %s: %m",
				path);
		return FALSE;
	}

	if (mmap_base == NULL) {
		/* empty file */
		return TRUE;
	}

	mail_index_update_headers(update, mmap_base, mmap_length, NULL, NULL);
	(void)munmap(mmap_base, mmap_length);
	return TRUE;
}
