/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index-private.h"
#include "mail-transaction-log.h"

int mail_index_reset(struct mail_index *index)
{
	struct mail_index_header hdr;

	/* this invalidates all views even if we fail later */
	index->indexid = 0;

	if (mail_index_mark_corrupted(index) < 0)
		return -1;

	mail_index_header_init(&hdr);
	if (hdr.indexid == index->indexid)
		hdr.indexid++;

	// FIXME: close it? ..
	if (mail_index_create(index, &hdr) < 0)
		return -1;

	/* reopen transaction log - FIXME: doesn't work, we have log views
	   open.. */
        mail_transaction_log_close(index->log);
	index->log = mail_transaction_log_open_or_create(index);
	if (index->log == NULL) {
		/* FIXME: creates potential crashes.. */
		return -1;
	}

	return 0;
}
