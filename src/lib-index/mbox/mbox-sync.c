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
	uoff_t offset;

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
		if (mbox_mail_get_start_offset(index, rec, &offset))
			offset += rec->header_size + rec->body_size;
	}

	if (index->lock_type == MAIL_LOCK_SHARED)
		(void)mail_index_set_lock(index, MAIL_LOCK_UNLOCK);

	if (offset > OFF_T_MAX) {
		/* too large to fit in off_t */
		return 0;
	}

	return offset;
}

int mbox_index_sync(MailIndex *index)
{
	struct stat st;
	MailLockType lock_type;
	time_t index_mtime;
	uoff_t filesize;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	lock_type = index->mbox_lock_next_sync;
	index->mbox_lock_next_sync = MAIL_LOCK_UNLOCK;
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

	if (lock_type != MAIL_LOCK_UNLOCK) {
		if (!mbox_lock(index, lock_type))
			return FALSE;
	}

	if (index_mtime == st.st_mtime && index->mbox_size == filesize)
		return TRUE;

	mbox_file_close_inbuf(index);

	/* problem .. index->mbox_size points to data after the last message.
	   that should be \n, \r\n, or end of file. modify filesize
	   accordingly to allow any of the extra 0-2 bytes. Don't actually
	   bother to open the file and verify it, it'd just slow things.. */
	index->mbox_size = get_indexed_mbox_size(index);
	if (filesize == index->mbox_size+1 ||
	    filesize == index->mbox_size+2)
		index->mbox_size = filesize;

	if (index->file_sync_stamp == 0 && index->mbox_size == filesize) {
		/* just opened the mailbox, and the file size is same as
		   we expected. don't bother checking it any further. */
		index->file_sync_stamp = st.st_mtime;
		return TRUE;
	}

	index->file_sync_stamp = st.st_mtime;

	/* file has changed, scan through the whole mbox */
	return mbox_sync_full(index);
}
