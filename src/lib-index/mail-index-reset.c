/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index-private.h"
#include "mail-transaction-log.h"

static int mail_index_mark_corrupted(struct mail_index *index)
{
	struct mail_index_header hdr;

	if (index->readonly)
		return 0;

	/* make sure we can write the header */
	if (!MAIL_INDEX_MAP_IS_IN_MEMORY(index->map)) {
		if (mprotect(index->map->mmap_base, sizeof(hdr),
			     PROT_READ | PROT_WRITE) < 0) {
			mail_index_set_syscall_error(index, "mprotect()");
			return -1;
		}
	}

	hdr = *index->hdr;
	hdr.flags |= MAIL_INDEX_HDR_FLAG_CORRUPTED;
	if (mail_index_write_header(index, &hdr) < 0)
		return -1;

	if (fsync(index->fd) < 0)
		return mail_index_set_syscall_error(index, "fsync()");

	mail_index_set_inconsistent(index);
	return 0;
}

int mail_index_reset(struct mail_index *index)
{
	struct mail_transaction_log *log;
	struct mail_index_header hdr;
	uint32_t file_seq;
	uoff_t file_offset;
	int log_locked;

	mail_index_header_init(&hdr);
	if (hdr.indexid == index->indexid)
		hdr.indexid++;

	if (mail_index_mark_corrupted(index) < 0)
		return -1;

	/*log_locked = index->log_locked;
	if (log_locked)
                mail_transaction_log_sync_unlock(index->log);

	log = index->log;
	mail_index_close(index);
	index->log = log;

	if (mail_index_open(index, MAIL_INDEX_OPEN_FLAG_CREATE |
			    MAIL_INDEX_OPEN_FLAG_REOPEN) < 0)
		return -1;

	if (log_locked) {
		if (mail_transaction_log_sync_lock(index->log,
						   &file_seq, &file_offset) < 0)
			return -1;
	}*/

	return 0;
}
