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
	int fd, failed;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (!mail_index_set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* reset the header */
	mail_index_init_header(index->header);
	index->mmap_used_length = index->header->used_file_size;

	/* we require MD5 to be cached */
	index->header->cache_fields |= FIELD_TYPE_MD5;

	/* update indexid, which also means that our state has completely
	   changed */
	index->indexid = index->header->indexid;
	index->inconsistent = TRUE;

	if (msync(index->mmap_base, sizeof(MailIndexHeader), MS_SYNC) < 0)
		return index_set_syscall_error(index, "msync()");

	/* reset data file */
	if (!mail_index_data_reset(index->data))
		return FALSE;

	/* open the mbox file. we don't really need to open it read-write,
	   but fcntl() locking requires it. */
	fd = open(index->mbox_path, O_RDWR);
	if (fd == -1)
		return mbox_set_syscall_error(index, "open()");

	/* lock the mailbox so we can be sure no-one interrupts us. */
	if (!mbox_lock(index, index->mbox_path, fd)) {
		(void)close(fd);
		return FALSE;
	}

	inbuf = io_buffer_create_mmap(fd, default_pool,
				      MAIL_MMAP_BLOCK_SIZE, 0);
	mbox_skip_empty_lines(inbuf);
	failed = !mbox_index_append(index, inbuf);

	(void)mbox_unlock(index, index->mbox_path, fd);
	(void)close(fd);
	io_buffer_destroy(inbuf);

	if (failed)
		return FALSE;

	/* update sync stamp */
	if (stat(index->mbox_path, &st) == -1)
		return mbox_set_syscall_error(index, "fstat()");

	index->file_sync_stamp = st.st_mtime;

	/* rebuild is complete - remove the flag */
	index->header->flags &= ~(MAIL_INDEX_FLAG_REBUILD|MAIL_INDEX_FLAG_FSCK);
	return TRUE;
}
