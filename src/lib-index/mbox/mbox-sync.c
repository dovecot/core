/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static uoff_t get_indexed_mbox_size(struct mail_index *index)
{
	struct mail_index_record *rec;
	uoff_t offset, hdr_size, body_size;

	if (index->lock_type == MAIL_LOCK_UNLOCK) {
		if (!mail_index_set_lock(index, MAIL_LOCK_SHARED))
			return 0;
	}

	/* get the last record */
	rec = index->header->messages_count == 0 ? NULL :
		index->lookup(index, index->header->messages_count);

	offset = 0;
	if (rec != NULL) {
		/* get the offset + size of last message, which tells the
		   last known mbox file size */
		if (mbox_mail_get_location(index, rec, &offset,
					   &hdr_size, &body_size))
			offset += hdr_size + body_size;
	}

	if (offset > OFF_T_MAX) {
		/* too large to fit in off_t */
		return 0;
	}

	return offset + 1; /* +1 for trailing \n */
}

static int mbox_lock_and_sync_full(struct mail_index *index,
				   enum mail_lock_type data_lock_type)
{
        enum mail_lock_type lock_type;

	/* syncing needs exclusive index lock and shared
	   mbox lock, but if we'd want exclusive mbox lock
	   we need to set it here already */
	if (index->lock_type == MAIL_LOCK_SHARED)
		(void)mail_index_set_lock(index, MAIL_LOCK_UNLOCK);

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (index->mbox_lock_type == MAIL_LOCK_UNLOCK) {
		lock_type = data_lock_type == MAIL_LOCK_EXCLUSIVE ?
			MAIL_LOCK_EXCLUSIVE : MAIL_LOCK_SHARED;
		if (!mbox_lock(index, lock_type))
			return FALSE;
	}

	return mbox_sync_full(index);
}

int mbox_index_sync(struct mail_index *index, int minimal_sync __attr_unused__,
		    enum mail_lock_type data_lock_type, int *changes)
{
	struct stat st;
	uoff_t filesize;
	int count, fd;

	if (index->mailbox_readonly && data_lock_type == MAIL_LOCK_EXCLUSIVE) {
		index_set_error(index, "sync: %s is read-only, "
				"can't get exclusive lock",
				index->mailbox_path);
		return FALSE;
	}

	if (changes != NULL)
		*changes = FALSE;

	if (index->mbox_sync_counter == index->mbox_lock_counter) {
		/* we've already synced in this locking session */
		return TRUE;
	}

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	count = 0;
	while (stat(index->mailbox_path, &st) < 0) {
		if (errno != ENOENT || ++count == 3)
			return mbox_set_syscall_error(index, "stat()");

		/* mbox was deleted by someone - happens with some MUAs
		   when all mail is expunged. easiest way to deal with this
		   is to recreate the file. */
		fd = open(index->mailbox_path, O_RDWR | O_CREAT | O_EXCL, 0660);
		if (fd != -1)
			(void)close(fd);
		else if (errno != EEXIST)
			return mbox_set_syscall_error(index, "open()");
	}
	filesize = st.st_size;

	if (index->mbox_ino != st.st_ino ||
            !CMP_DEV_T(index->mbox_dev, st.st_dev)) {
		/* mbox file was overwritten, close it if it was open */
		index->mbox_dev = st.st_dev;
		index->mbox_ino = st.st_ino;
		index->mbox_size = (uoff_t)-1;

                mbox_file_close_fd(index);
	}

	if (index->mbox_sync_counter == 0) {
		/* first sync, get expected mbox size */
		index->mbox_size = get_indexed_mbox_size(index);
	}

	if (index->sync_stamp != st.st_mtime || index->mbox_size != filesize) {
		mbox_file_close_stream(index);

		if (changes != NULL)
			*changes = TRUE;

		if (!mbox_lock_and_sync_full(index, data_lock_type))
			return FALSE;

		if ((index->set_flags & MAIL_INDEX_HDR_FLAG_REBUILD) != 0) {
			/* uidvalidity probably changed, rebuild */
			if (!index->rebuild(index))
				return FALSE;
		}

		index->mbox_size = filesize;
		index->sync_stamp = st.st_mtime;
	}

	/* we need some index lock to be able to lock mbox */
	if (index->lock_type == MAIL_LOCK_UNLOCK) {
		if (!index->set_lock(index, MAIL_LOCK_SHARED))
			return FALSE;
	}

	if (data_lock_type == MAIL_LOCK_UNLOCK) {
		if (!mbox_unlock(index))
			return FALSE;
	} else {
		if (!mbox_lock(index, data_lock_type))
			return FALSE;
	}

	index->mbox_sync_counter = index->mbox_lock_counter;
	return TRUE;
}
