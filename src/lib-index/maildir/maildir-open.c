/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "maildir-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

IStream *maildir_open_mail(MailIndex *index, MailIndexRecord *rec,
			   time_t *internal_date, int *deleted)
{
	struct stat st;
	const char *fname, *path;
	int fd;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*deleted = FALSE;

	/* check for inconsistency here, to avoid extra error messages */
	if (index->inconsistent)
		return NULL;

	fname = index->lookup_field(index, rec, DATA_FIELD_LOCATION);
	if (fname == NULL) {
		index_data_set_corrupted(index->data,
			"Missing location field for record %u", rec->uid);
		return NULL;
	}

	path = t_strconcat(index->dir, "/cur/", fname, NULL);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT) {
			*deleted = TRUE;
			return NULL;
		}

		index_set_error(index, "Error opening mail file %s: %m", path);
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
