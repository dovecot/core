/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "hex-binary.h"
#include "mbox-index.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static uoff_t get_indexed_mbox_size(MailIndex *index)
{
	MailIndexRecord *rec, *prev;
	const char *location;
	uoff_t size;

	if (index->lock_type == MAIL_LOCK_UNLOCK) {
		if (!mail_index_set_lock(index, MAIL_LOCK_SHARED))
			return 0;
	}

	/* get the last record */
	rec = index->header->messages_count == 0 ? NULL :
		index->lookup(index, index->header->messages_count);
	if (rec == NULL) {
		rec = prev = index->lookup(index, 1);
		while (rec != NULL) {
			prev = rec;
			rec = index->next(index, rec);
		}

		rec = prev;
	}

	size = 0;
	if (rec != NULL) {
		/* get the offset + size of last message, which tells the
		   last known mbox file size */
		location = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
		if (location == NULL) {
			INDEX_MARK_CORRUPTED(index);
			index_set_error(index, "Corrupted index file %s: "
					"Missing location field for record %u",
					index->filepath, rec->uid);
		} else if (strlen(location) != sizeof(size)*2 ||
			   hex_to_binary(location,
					 (unsigned char *) &size) <= 0) {
			INDEX_MARK_CORRUPTED(index);
			index_set_error(index, "Corrupted index file %s: "
					"Invalid location field for record %u",
					index->filepath, rec->uid);
		} else {
			size += rec->header_size + rec->body_size;
		}
	}

	if (index->lock_type == MAIL_LOCK_SHARED)
		(void)mail_index_set_lock(index, MAIL_LOCK_UNLOCK);

	if (size > OFF_T_MAX) {
		/* too large to fit in off_t */
		return 0;
	}

	return size;
}

static int mbox_check_new_mail(MailIndex *index)
{
	IOBuffer *inbuf;
	off_t pos;
	int fd, ret;

	fd = open(index->mbox_path, O_RDONLY);
	if (fd == -1) {
		index_set_error(index, "Can't open mbox file %s: %m",
				index->mbox_path);
		return FALSE;
	}

	pos = lseek(fd, (off_t)index->mbox_size, SEEK_SET);
	if (pos == -1) {
		index_set_error(index, "lseek() failed with mbox file %s: %m",
				index->mbox_path);
		(void)close(fd);
		return FALSE;
	}

	if ((uoff_t)pos != index->mbox_size) {
		/* someone just shrinked the file? */
		(void)close(fd);
		return mbox_index_fsck(index);
	}

	/* add the new data */
	inbuf = io_buffer_create_mmap(fd, default_pool,
				      MAIL_MMAP_BLOCK_SIZE, 0);
	ret = mbox_index_append(index, inbuf);
	(void)close(fd);
	io_buffer_destroy(inbuf);

	if (index->set_flags & MAIL_INDEX_FLAG_FSCK) {
		/* it wasn't just new mail, reread the mbox */
		index->set_flags &= ~MAIL_INDEX_FLAG_FSCK;
		return mbox_index_fsck(index);
	}

	return ret;
}

int mbox_index_sync(MailIndex *index)
{
	struct stat st;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (stat(index->mbox_path, &st) == -1) {
		index_set_error(index, "stat() failed with mbox file %s: %m",
				index->mbox_path);
		return FALSE;
	}

	if (index->file_sync_stamp == st.st_mtime)
		return TRUE;

	index->file_sync_stamp = st.st_mtime;

	if (index->mbox_size == 0 && st.st_size != 0)
		index->mbox_size = get_indexed_mbox_size(index);

	/* file has been modified. */
	if (index->mbox_size > (uoff_t)st.st_size) {
		/* file was grown, hopefully just new mail */
		return mbox_check_new_mail(index);
	} else {
		/* something changed, scan through the whole mbox */
		return mbox_index_fsck(index);
	}
}
