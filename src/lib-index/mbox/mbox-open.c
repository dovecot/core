/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "hex-binary.h"
#include "mbox-index.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

IOBuffer *mbox_open_mail(MailIndex *index, MailIndexRecord *rec)
{
	const char *location;
	uoff_t offset, stop_offset;
	off_t pos;
	char buf[7], *p;
	int fd, ret, failed;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	location = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
	if (location == NULL) {
                INDEX_MARK_CORRUPTED(index);
		index_set_error(index, "Corrupted index file %s: "
				"Missing location field for record %u",
				index->filepath, rec->uid);
		return NULL;
	}

	/* location = offset in hex */
	if (strlen(location) != sizeof(offset)*2 ||
	    hex_to_binary(location, (unsigned char *) &offset) <= 0 ||
	    offset > OFF_T_MAX) {
                INDEX_MARK_CORRUPTED(index);
		index_set_error(index, "Corrupted index file %s: "
				"Invalid location field for record %u",
				index->filepath, rec->uid);
		return NULL;
	}

	stop_offset = offset + rec->header_size + rec->body_size;

	fd = open(index->mbox_path, O_RDONLY);
	if (fd == -1) {
		index_set_error(index, "Can't open mbox file %s: %m",
				index->mbox_path);
		return NULL;
	}

	pos = lseek(fd, (off_t)offset, SEEK_SET);
	if (pos == -1) {
		index_set_error(index, "lseek() failed with mbox file %s: %m",
				index->mbox_path);
		(void)close(fd);
		return NULL;
	}

	failed = TRUE;
	if ((uoff_t)pos == offset) {
		/* make sure message size is valid */
		if (lseek(fd, (off_t)stop_offset, SEEK_SET) ==
		    (off_t)stop_offset) {
			/* and check that we end with either EOF or to
			   beginning of next message */
			ret = read(fd, buf, 7);
			if (ret >= 6) {
				/* "[\r]\nFrom " expected */
				if (buf[0] != '\r')
					p = buf;
				else {
					p = buf+1;
					ret--;
				}
				if (ret >= 6 && strncmp(p, "\nFrom ", 6) == 0)
					failed = FALSE;
			} else {
				p = buf;
				if (ret > 0 && *p == '\r') {
					p++;
					ret--;
				}
				if (ret > 0 && *p == '\n')
					ret--;

				if (ret == 0)
					failed = FALSE; /* end of file */
			}
		}
	}

	if (!failed) {
		if (lseek(fd, (off_t)offset, SEEK_SET) == (off_t)offset) {
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

		index_set_error(index, "mbox file %s was modified "
				"unexpectedly, fscking", index->mbox_path);
	}

	(void)close(fd);
	return NULL;
}
