/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "maildir-index.h"
#include "mail-index-util.h"
#include "mail-cache.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int do_open(struct mail_index *index, const char *path, void *context)
{
	int *fd = context;

	*fd = open(path, O_RDONLY);
	if (*fd != -1)
		return 1;
	if (errno == ENOENT)
		return 0;

	index_file_set_syscall_error(index, path, "open()");
	return -1;
}

struct istream *maildir_open_mail(struct mail_index *index,
				  struct mail_index_record *rec,
				  time_t *received_date, int *deleted)
{
	struct stat st;
	int fd;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*deleted = FALSE;

	/* check for inconsistency here, to avoid extra error messages */
	if (index->inconsistent)
		return NULL;

	fd = -1;
	if (!maildir_file_do(index, rec, do_open, &fd))
		return NULL;

	if (fd == -1) {
		*deleted = TRUE;
		return NULL;
	}

	if (received_date != NULL) {
		if (fstat(fd, &st) == 0)
			*received_date = st.st_mtime;
	}

	if (index->mail_read_mmaped) {
		return i_stream_create_mmap(fd, default_pool,
					    MAIL_MMAP_BLOCK_SIZE, 0, 0, TRUE);
	} else {
		return i_stream_create_file(fd, default_pool,
					    MAIL_READ_BLOCK_SIZE, TRUE);
	}
}
