/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "mbox-storage.h"
#include "mbox-lock.h"
#include "mbox-sync-private.h"

struct mailbox_transaction_context *
mbox_transaction_begin(struct mailbox *box, int hide)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct mbox_transaction_context *t;

	t = i_new(struct mbox_transaction_context, 1);
        index_transaction_init(&t->ictx, ibox, hide);
	return &t->ictx.mailbox_ctx;
}

int mbox_transaction_commit(struct mailbox_transaction_context *_t)
{
	struct mbox_transaction_context *t =
		(struct mbox_transaction_context *)_t;
	struct index_mailbox *ibox = t->ictx.ibox;
	unsigned int lock_id = t->mbox_lock_id;
	int mbox_modified, ret = 0;

	if (t->save_ctx != NULL)
		ret = mbox_save_commit(t->save_ctx);
	mbox_modified = t->mbox_modified;

	if (ret == 0) {
		if (index_transaction_commit(_t) < 0)
			ret = -1;
	} else {
		index_transaction_rollback(_t);
	}
	t = NULL;

	if (ret == 0) {
		if (mbox_sync(ibox, TRUE, mbox_modified, FALSE) < 0)
			ret = -1;
	}

	if (lock_id != 0) {
		if (mbox_unlock(ibox, lock_id) < 0)
			ret = -1;
	}
	return ret;
}

void mbox_transaction_rollback(struct mailbox_transaction_context *_t)
{
	struct mbox_transaction_context *t =
		(struct mbox_transaction_context *)_t;
	struct index_mailbox *ibox = t->ictx.ibox;

	if (t->save_ctx != NULL)
		mbox_save_rollback(t->save_ctx);

	if (t->mbox_lock_id != 0)
		(void)mbox_unlock(ibox, t->mbox_lock_id);
	index_transaction_rollback(_t);
}
