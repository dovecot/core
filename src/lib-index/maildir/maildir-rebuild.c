/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"
#include "mail-tree.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

int maildir_index_rebuild(struct mail_index *index)
{
	if (!mail_index_set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* reset the header */
	mail_index_init_header(index, index->header);
	index->mmap_used_length = index->header->used_file_size;

	/* require these fields */
	index->header->cache_fields |= DATA_FIELD_LOCATION;

	/* update indexid, which also means that our state has completely
	   changed */
	index->indexid = index->header->indexid;
	index->inconsistent = TRUE;
	index->rebuilding = TRUE;

	if (!index->anon_mmap) {
		if (msync(index->mmap_base,
			  sizeof(struct mail_index_header), MS_SYNC) < 0)
			return index_set_syscall_error(index, "msync()");
	}

	/* reset data file */
	if (!mail_index_data_reset(index->data))
		return FALSE;

	/* read the mails by syncing */
	if (!index->sync_and_lock(index, FALSE, MAIL_LOCK_UNLOCK, NULL))
		return FALSE;

	/* rebuild is complete - remove the flag */
	index->header->flags &= ~(MAIL_INDEX_FLAG_REBUILD|MAIL_INDEX_FLAG_FSCK);
	index->rebuilding = FALSE;
	return TRUE;
}
