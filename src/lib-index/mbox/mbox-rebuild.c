/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mbox-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

int mbox_index_rebuild(struct mail_index *index)
{
	struct stat st;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (!mail_index_set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* reset the header */
	mail_index_init_header(index, index->header);
	index->mmap_used_length = index->header->used_file_size;

	/* require these fields */
	index->header->cache_fields |= DATA_FIELD_LOCATION |
		DATA_FIELD_MESSAGEPART | DATA_FIELD_MD5;

	/* update indexid, which also means that our state has completely
	   changed */
	index->indexid = index->header->indexid;
	if (index->opened)
		index->inconsistent = TRUE;

	if (!index->anon_mmap) {
		if (msync(index->mmap_base,
			  sizeof(struct mail_index_header), MS_SYNC) < 0)
			return index_set_syscall_error(index, "msync()");
	}

	/* reset data file */
	if (!mail_index_data_reset(index->data))
		return FALSE;

	if (!mbox_sync_full(index))
		return FALSE;

	/* update sync stamp */
	if (stat(index->mailbox_path, &st) < 0)
		return mbox_set_syscall_error(index, "fstat()");

	index->file_sync_stamp = st.st_mtime;

	/* rebuild is complete - remove the flag */
	index->header->flags &= ~(MAIL_INDEX_FLAG_REBUILD|MAIL_INDEX_FLAG_FSCK);
	index->set_flags &= ~MAIL_INDEX_FLAG_REBUILD;
	return TRUE;
}
