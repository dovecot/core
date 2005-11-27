/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "dbox-sync.h"
#include "dbox-storage.h"

struct mailbox_transaction_context *
dbox_transaction_begin(struct mailbox *box,
		       enum mailbox_transaction_flags flags)
{
	struct dbox_mailbox *dbox = (struct dbox_mailbox *)box;
	struct dbox_transaction_context *t;

	t = i_new(struct dbox_transaction_context, 1);
	index_transaction_init(&t->ictx, &dbox->ibox, flags);
	return &t->ictx.mailbox_ctx;
}

int dbox_transaction_commit(struct mailbox_transaction_context *_t,
			    enum mailbox_sync_flags flags)
{
	struct dbox_transaction_context *t =
		(struct dbox_transaction_context *)_t;
	struct dbox_mailbox *dbox = (struct dbox_mailbox *)t->ictx.ibox;
	struct dbox_save_context *save_ctx;
	int ret = 0;

	if (t->save_ctx != NULL) {
		if (dbox_transaction_save_commit_pre(t->save_ctx) < 0) {
			t->save_ctx = NULL;
			ret = -1;
		}
	}

	save_ctx = t->save_ctx;

	if (ret == 0) {
		if (index_transaction_commit(_t) < 0)
			ret = -1;
	} else {
		index_transaction_rollback(_t);
	}
	/* transaction is destroyed. */
	t = NULL; _t = NULL;

	if (save_ctx != NULL) {
		/* unlock uidlist file after writing to transaction log,
		   to make sure we don't write uids in wrong order. */
		dbox_transaction_save_commit_post(save_ctx);
	}

#if 0
	if (lock_id != 0 && dbox->dbox_lock_type != F_WRLCK) {
		/* unlock before writing any changes */
		(void)dbox_unlock(dbox, lock_id);
		lock_id = 0;
	}
#endif
	if (ret == 0) {
		if (dbox_sync(dbox, FALSE) < 0)
			ret = -1;
	}

#if 0
	if (lock_id != 0) {
		if (dbox_unlock(dbox, lock_id) < 0)
			ret = -1;
	}
#endif
	return ret;
}

void dbox_transaction_rollback(struct mailbox_transaction_context *_t)
{
	struct dbox_transaction_context *t =
		(struct dbox_transaction_context *)_t;
	struct dbox_mailbox *dbox = (struct dbox_mailbox *)t->ictx.ibox;

	if (t->save_ctx != NULL)
		dbox_transaction_save_rollback(t->save_ctx);

	/*if (t->dbox_lock_id != 0)
		(void)dbox_unlock(dbox, t->dbox_lock_id);*/
	index_transaction_rollback(_t);
}
