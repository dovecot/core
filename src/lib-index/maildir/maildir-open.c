/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "maildir-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int maildir_open_mail_file(struct mail_index *index,
				  struct mail_index_record *rec,
				  const char **fname, int *deleted)
{
	const char *path;
	int fd = -1;

	*fname = maildir_get_location(index, rec);
	if (*fname == NULL)
		return -1;

	if ((rec->index_flags & INDEX_MAIL_FLAG_MAILDIR_NEW) != 0) {
		/* probably in new/ dir */
		path = t_strconcat(index->mailbox_path, "/new/", *fname, NULL);
		fd = open(path, O_RDONLY);
		if (fd == -1 && errno != ENOENT) {
			index_set_error(index, "open(%s) failed: %m", path);
			return -1;
		}
	}

	if (fd == -1) {
		path = t_strconcat(index->mailbox_path, "/cur/", *fname, NULL);
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			if (errno == ENOENT) {
				*deleted = TRUE;
				return -1;
			}

			index_set_error(index, "open(%s) failed: %m", path);
			return -1;
		}
	}

	return fd;
}

struct istream *maildir_open_mail(struct mail_index *index,
				  struct mail_index_record *rec,
				  time_t *internal_date, int *deleted)
{
	struct stat st;
	const char *fname;
	int i, found, fd;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*deleted = FALSE;

	/* check for inconsistency here, to avoid extra error messages */
	if (index->inconsistent)
		return NULL;

	fd = maildir_open_mail_file(index, rec, &fname, deleted);
	for (i = 0; fd == -1 && *deleted && i < 10; i++) {
		/* file is either renamed or deleted. sync the maildir and
		   see which one. if file appears to be renamed constantly,
		   don't try to open it more than 10 times. */
		if (!maildir_index_sync_readonly(index, fname, &found)) {
			*deleted = FALSE;
			return NULL;
		}

		if (!found) {
			/* syncing didn't find it, it's deleted */
			return NULL;
		}

		fd = maildir_open_mail_file(index, rec, &fname, deleted);
		if (fd == -1)
			return NULL;
	}

	if (internal_date != NULL) {
		*internal_date = mail_get_internal_date(index, rec);

		if (*internal_date == (time_t)-1) {
			if (fstat(fd, &st) == 0)
				*internal_date = st.st_mtime;
		}
	}

	if (index->mail_read_mmaped) {
		return i_stream_create_mmap(fd, default_pool,
					    MAIL_MMAP_BLOCK_SIZE, 0, 0, TRUE);
	} else {
		return i_stream_create_file(fd, default_pool,
					    MAIL_READ_BLOCK_SIZE, TRUE);
	}
}
