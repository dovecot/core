/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static uoff_t get_indexed_mbox_size(MailIndex *index)
{
	MailIndexRecord *rec;
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

static int mbox_lock_and_sync_full(MailIndex *index,
				   MailLockType data_lock_type)
{
        MailLockType lock_type;

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

int mbox_index_sync(MailIndex *index, MailLockType data_lock_type,
		    int *changes)
{
	struct stat st;
	time_t index_mtime;
	uoff_t filesize;
	int count, fd;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (changes != NULL)
		*changes = FALSE;

	if (index->mbox_sync_counter == index->mbox_lock_counter) {
		/* we've already synced in this locking session */
		return TRUE;
	}

	if (index->fd == -1) {
		/* anon-mmaped */
		index_mtime = index->file_sync_stamp;
	} else {
		if (fstat(index->fd, &st) < 0)
			return index_set_syscall_error(index, "fstat()");
		index_mtime = st.st_mtime;
	}

	count = 0;
	while (stat(index->mbox_path, &st) < 0) {
		if (errno != ENOENT || ++count == 3)
			return mbox_set_syscall_error(index, "stat()");

		/* mbox was deleted by someone - happens with some MUAs
		   when all mail is expunged. easiest way to deal with this
		   is to recreate the file. */
		fd = open(index->mbox_path, O_RDWR | O_CREAT | O_EXCL, 0660);
		if (fd != -1)
			(void)close(fd);
		else if (errno != EEXIST)
			return mbox_set_syscall_error(index, "open()");
	}
	filesize = st.st_size;

	if (index->mbox_ino != st.st_ino ||
	    major(index->mbox_dev) != major(st.st_dev) ||
	    minor(index->mbox_dev) != minor(st.st_dev)) {
		/* mbox file was overwritten, close it if it was open */
		index->mbox_dev = st.st_dev;
		index->mbox_ino = st.st_ino;
		index->mbox_size = (uoff_t)-1;

                mbox_file_close_fd(index);
	}

	if (index_mtime != st.st_mtime || index->mbox_size != filesize) {
		mbox_file_close_inbuf(index);

		index->mbox_size = get_indexed_mbox_size(index);
		if (index->file_sync_stamp == 0 &&
		    index->mbox_size == filesize) {
			/* just opened the mailbox, and the file size is same
			   as we expected. don't bother checking it any
			   further. */
		} else {
			if (changes != NULL)
				*changes = TRUE;

			if (!mbox_lock_and_sync_full(index, data_lock_type))
				return FALSE;

			index->mbox_size = filesize;
		}

		index->file_sync_stamp = st.st_mtime;
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
