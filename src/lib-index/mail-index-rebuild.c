/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-cache.h"

#include <sys/mman.h>

int mail_index_rebuild(struct mail_index *index)
{
	if (!mail_index_set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	index->set_flags &= ~MAIL_INDEX_HDR_FLAG_REBUILD;

	/* reset the header */
	mail_index_init_header(index->header);
	index->mmap_used_length = index->header->used_file_size;

	/* update indexid, which also means that our state has completely
	   changed */
	index->indexid = index->header->indexid;
	index->inconsistent = TRUE;
	index->rebuilding = TRUE;

	if (!index->anon_mmap) {
		if (msync(index->mmap_base, index->header_size, MS_SYNC) < 0)
			return index_set_syscall_error(index, "msync()");
	}

	if (!mail_cache_truncate(index->cache))
		return FALSE;

	/* read the mails by syncing */
	if (!index->sync_and_lock(index, FALSE, MAIL_LOCK_UNLOCK, NULL))
		return FALSE;

	/* rebuild is complete - remove the flag */
	index->header->flags &= ~(MAIL_INDEX_HDR_FLAG_REBUILD |
				  MAIL_INDEX_HDR_FLAG_FSCK);
	index->header->flags |= index->set_flags;
	index->set_flags = 0;

	index->rebuilding = FALSE;
	return TRUE;
}
