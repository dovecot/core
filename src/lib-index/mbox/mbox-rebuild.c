/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-data.h"
#include "mail-index-util.h"
#include "mail-hash.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

int mbox_index_rebuild(MailIndex *index)
{
	IOBuffer *inbuf;
	struct stat st;
	int fd;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (!mail_index_set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* reset the header */
	mail_index_init_header(index->header);

	/* we require MD5 to be cached */
	index->header->cache_fields |= FIELD_TYPE_MD5;

	/* update indexid */
	index->indexid = index->header->indexid;

	if (msync(index->mmap_base, sizeof(MailIndexHeader), MS_SYNC) == -1) {
		index_set_error(index, "msync() failed for index file %s: %m",
				index->filepath);
		return FALSE;
	}

	/* truncate the file first, so it won't contain
	   any invalid data even if we crash */
	if (ftruncate(index->fd, sizeof(MailIndexHeader)) == -1) {
		index_set_error(index, "Can't truncate index file %s: %m",
				index->filepath);
		return FALSE;
	}

	/* reset data file */
	if (!mail_index_data_reset(index->data))
		return FALSE;

	/* open the mbox file. we don't really need to open it read-write,
	   but fcntl() locking requires it. */
	fd = open(index->mbox_path, O_RDWR);
	if (fd == -1) {
		index_set_error(index, "Error opening mbox file %s: %m",
				index->mbox_path);
		return FALSE;
	}

	/* lock the mailbox so we can be sure no-one interrupts us. */
	if (!mbox_lock(index, index->mbox_path, fd)) {
		(void)close(fd);
		return FALSE;
	}

	inbuf = io_buffer_create_mmap(fd, default_pool,
				      MAIL_MMAP_BLOCK_SIZE, -1);
	if (!mbox_index_append(index, inbuf)) {
		(void)mbox_unlock(index, index->mbox_path, fd);
		(void)close(fd);
		return FALSE;
	}

	(void)mbox_unlock(index, index->mbox_path, fd);
	(void)close(fd);
	io_buffer_destroy(inbuf);

	/* update sync stamp */
	if (stat(index->mbox_path, &st) == -1) {
		index_set_error(index, "fstat() failed for mbox file %s: %m",
				index->mbox_path);
		return FALSE;
	}

	index->file_sync_stamp = st.st_mtime;

	/* rebuild is complete - remove the flag */
	index->header->flags &= ~(MAIL_INDEX_FLAG_REBUILD|MAIL_INDEX_FLAG_FSCK);
	return TRUE;
}
