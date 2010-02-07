/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "hex-binary.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"
#include "sdbox-sync.h"

#include <stdlib.h>

static void
dbox_sync_file_move_if_needed(struct dbox_file *file,
			      enum sdbox_sync_entry_type type)
{
	bool move_to_alt = type == SDBOX_SYNC_ENTRY_TYPE_MOVE_TO_ALT;
	
	if (move_to_alt != dbox_file_is_in_alt(file)) {
		/* move the file. if it fails, nothing broke so
		   don't worry about it. */
		if (dbox_file_try_lock(file) > 0) {
			(void)dbox_file_move(file, move_to_alt);
			dbox_file_unlock(file);
		}
	}
}

static void
dbox_sync_mark_single_file_expunged(struct sdbox_sync_context *ctx,
				    const struct sdbox_sync_file_entry *entry)
{
	struct mailbox *box = &ctx->mbox->box;
	uint32_t seq;

	mail_index_lookup_seq(ctx->sync_view, entry->uid, &seq);
	mail_index_expunge(ctx->trans, seq);

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, entry->uid, MAILBOX_SYNC_TYPE_EXPUNGE);
}

int sdbox_sync_file(struct sdbox_sync_context *ctx,
		    const struct sdbox_sync_file_entry *entry)
{
	struct sdbox_mailbox *mbox = ctx->mbox;
	struct dbox_file *file;
	int ret = 1;

	file = sdbox_file_init(mbox, entry->uid);
	switch (entry->type) {
	case SDBOX_SYNC_ENTRY_TYPE_EXPUNGE:
		if (dbox_file_unlink(file) >= 0) {
			dbox_sync_mark_single_file_expunged(ctx, entry);
			ret = 1;
		}
		break;
	case SDBOX_SYNC_ENTRY_TYPE_MOVE_FROM_ALT:
	case SDBOX_SYNC_ENTRY_TYPE_MOVE_TO_ALT:
		dbox_sync_file_move_if_needed(file, entry->type);
		break;
	}
	dbox_file_unref(&file);
	return ret;
}
