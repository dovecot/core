/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "raw-storage.h"
#include "raw-sync.h"
#include "mailbox-recent-flags.h"

static int raw_sync(struct raw_mailbox *mbox)
{
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_sync_rec sync_rec;
	struct mail_index_transaction *trans;
	uint32_t seq, uid_validity = ioloop_time;
	enum mail_index_sync_flags sync_flags;
	int ret;

	i_assert(!mbox->synced);

	sync_flags = index_storage_get_sync_flags(&mbox->box) |
		MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY |
		MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;

	if (mail_index_view_get_messages_count(mbox->box.view) > 0) {
		/* already-synced index was opened via
		   mail-index-alloc-cache. */
		return 0;
	}

	ret = mail_index_sync_begin(mbox->box.index, &index_sync_ctx,
				    &sync_view, &trans, sync_flags);
	if (ret <= 0) {
		if (ret < 0)
			mailbox_set_index_error(&mbox->box);
		return ret;
	}

	/* set our uidvalidity */
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);

	/* add our one and only message */
	mail_index_append(trans, 1, &seq);
	mailbox_recent_flags_set_uid(&mbox->box, 1);

	while (mail_index_sync_next(index_sync_ctx, &sync_rec)) ;
	if (mail_index_sync_commit(&index_sync_ctx) < 0) {
		mailbox_set_index_error(&mbox->box);
		return -1;
	}
	mbox->synced = TRUE;
	return 0;
}

struct mailbox_sync_context *
raw_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct raw_mailbox *mbox = (struct raw_mailbox *)box;
	int ret = 0;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			ret = -1;
	}

	if (!mbox->synced && ret == 0)
		ret = raw_sync(mbox);

	return index_mailbox_sync_init(box, flags, ret < 0);
}
