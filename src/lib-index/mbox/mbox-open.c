/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "mbox-index.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

IOBuffer *mbox_open_mail(MailIndex *index, MailIndexRecord *rec)
{
	const char *location;
	off_t pos, offset, stop_offset;
	char buf[5];
	int fd, ret, ok;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	location = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
	if (location == NULL) {
                INDEX_MARK_CORRUPTED(index);
		index_set_error(index, "Corrupted index file %s: "
				"Missing location field for record %u",
				index->filepath, rec->uid);
		return NULL;
	}

	/* location = offset */
	offset = (off_t)strtoul(location, NULL, 10);
	stop_offset = offset + rec->header_size + rec->body_size;

	fd = open(index->mbox_path, O_RDONLY);
	if (fd == -1) {
		index_set_error(index, "Can't open mbox file %s: %m",
				index->mbox_path);
		return NULL;
	}

	pos = lseek(fd, offset, SEEK_SET);
	if (pos == -1) {
		index_set_error(index, "lseek() failed with mbox file %s: %m",
				index->mbox_path);
		(void)close(fd);
		return NULL;
	}

	ok = FALSE;
	if (pos == offset) {
		/* make sure message size is valid */
		if (lseek(fd, stop_offset, SEEK_SET) == stop_offset) {
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
		if (lseek(fd, offset, SEEK_SET) == offset) {
			/* everything ok */
			return io_buffer_create_mmap(fd, default_pool,
						     MAIL_MMAP_BLOCK_SIZE,
						     stop_offset);
		}


		index_set_error(index, "lseek() failed with mbox file %s: %m",
				index->mbox_path);
	} else {
		/* file has been updated, rescan it */
		index->set_flags |= MAIL_INDEX_FLAG_FSCK;
	}

	(void)close(fd);
	return NULL;
}
