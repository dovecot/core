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

	return offset;
}

int mbox_index_sync(MailIndex *index, MailLockType lock_type, int *changes)
{
	struct stat st;
	time_t index_mtime;
	uoff_t filesize;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (changes != NULL)
		*changes = FALSE;
	index->mbox_sync_counter = index->mbox_lock_counter;

	if (index->fd == -1) {
		/* anon-mmaped */
		index_mtime = index->file_sync_stamp;
	} else {
		if (fstat(index->fd, &st) < 0)
			return index_set_syscall_error(index, "fstat()");
		index_mtime = st.st_mtime;
	}

	if (stat(index->mbox_path, &st) < 0)
		return mbox_set_syscall_error(index, "stat()");
	filesize = st.st_size;

	if (index->mbox_dev != st.st_dev || index->mbox_ino != st.st_ino) {
		/* mbox file was overwritten, close it if it was open */
		index->mbox_dev = st.st_dev;
		index->mbox_ino = st.st_ino;
		index->mbox_size = (uoff_t)-1;

                mbox_file_close_fd(index);
	}

	if (lock_type == MAIL_LOCK_EXCLUSIVE) {
		/* if we know that we want exclusive lock, we might get
		   it immediately to save extra lock changes */
		if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
			return FALSE;
	}

	if (index_mtime != st.st_mtime || index->mbox_size != filesize) {
		mbox_file_close_inbuf(index);

		/* problem .. index->mbox_size points to data after the last
		   message. that should be \n or end of file. modify filesize
		   accordingly to allow the extra byte. Don't actually bother
		   to open the file and verify it, it'd just slow things.. */
		index->mbox_size = get_indexed_mbox_size(index);
		if (filesize == index->mbox_size+1)
			index->mbox_size = filesize;

		if (index->file_sync_stamp == 0 &&
		    index->mbox_size == filesize) {
			/* just opened the mailbox, and the file size is same
			   as we expected. don't bother checking it any
			   further. */
		} else {
			if (changes != NULL)
				*changes = TRUE;

			/* file has changed, scan through the whole mbox */
			if (!mbox_sync_full(index)) {
				(void)index->set_lock(index, MAIL_LOCK_UNLOCK);
				return FALSE;
			}

			if (lock_type == MAIL_LOCK_EXCLUSIVE &&
			    index->mbox_lock_type == MAIL_LOCK_SHARED) {
				/* mbox_sync_full() left it */
				if (!mbox_unlock(index))
					return FALSE;
			}
		}

		index->file_sync_stamp = st.st_mtime;
	}

	if (!index->set_lock(index, lock_type))
		return FALSE;

	if (lock_type != MAIL_LOCK_UNLOCK) {
		if (!mbox_lock(index, lock_type))
			return FALSE;
	} else {
		if (!mbox_unlock(index))
			return FALSE;
	}

	return TRUE;
}
