/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mbox-index.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int mbox_open_mail(MailIndex *index, MailIndexRecord *rec,
		   off_t *offset, size_t *size)
{
	const char *location;
	off_t pos;
	char buf[5];
	int fd, ret, ok;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	location = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
	if (location == NULL) {
                INDEX_MARK_CORRUPTED(index);
		index_set_error(index, "Corrupted index file %s: "
				"Missing location field for record %u",
				index->filepath, rec->uid);
		return -1;
	}

	/* location = offset */
	*offset = (off_t)strtoul(location, NULL, 10);
	*size = rec->header_size + rec->body_size;

	fd = open(index->mbox_path, O_RDONLY);
	if (fd == -1) {
		index_set_error(index, "Can't open mbox file %s: %m",
				index->mbox_path);
		return -1;
	}

	pos = lseek(fd, *offset, SEEK_SET);
	if (pos == (off_t)-1) {
		index_set_error(index, "lseek() failed with mbox file %s: %m",
				index->mbox_path);
		(void)close(fd);
		return -1;
	}

	ok = FALSE;
	if (pos == *offset) {
		/* make sure message size is valid */
		pos = *offset + *size;
		if (lseek(fd, pos, SEEK_SET) == pos) {
			/* and check that we end with either EOF or to
			   beginning of next message */
			ret = read(fd, buf, 5);
			if (ret == 0)
				ok = TRUE; /* end of file */
			else if (ret == 5 && strncmp(buf, "From ", 5) == 0)
				ok = TRUE;
		}
	}

	if (ok) {
		if (lseek(fd, *offset, SEEK_SET) == *offset)
			return fd;

		index_set_error(index, "lseek() failed with mbox file %s: %m",
				index->mbox_path);
	} else {
		/* file has been updated, rescan it */
		index->set_flags |= MAIL_INDEX_FLAG_FSCK;
	}

	(void)close(fd);
	return -1;
}
