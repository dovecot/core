/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <fcntl.h>

int maildir_open_mail(MailIndex *index, MailIndexRecord *rec,
		      off_t *offset, size_t *size)
{
	off_t pos;
	const char *fname, *path;
	int fd;

	fname = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
	if (fname == NULL) {
                INDEX_MARK_CORRUPTED(index);
		index_set_error(index, "Corrupted index file %s: "
				"Missing location field for record %u",
				index->filepath, rec->uid);
		return -1;
	}

	path = t_strconcat(index->dir, "/cur/", fname, NULL);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		index_set_error(index, "Error opening mail file %s: %m", path);
		return -1;
	}

	pos = lseek(fd, 0, SEEK_END);
	if (pos == (off_t)-1 || lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		index_set_error(index, "lseek() failed with mail file %s: %m",
				path);
		(void)close(fd);
		return -1;
	}

	*offset = 0;
	*size = (size_t) pos;
	return fd;
}
