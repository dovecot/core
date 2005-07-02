/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "maildir-storage.h"

struct mailbox_transaction_context *
maildir_transaction_begin(struct mailbox *box,
			  enum mailbox_transaction_flags flags)
{
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;
	struct maildir_transaction_context *t;

	t = i_new(struct maildir_transaction_context, 1);
	index_transaction_init(&t->ictx, &mbox->ibox, flags);
	return &t->ictx.mailbox_ctx;
}

int maildir_transaction_commit(struct mailbox_transaction_context *_t,
			       enum mailbox_sync_flags flags __attr_unused__)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)t->ictx.ibox;
	struct maildir_save_context *save_ctx;
	int ret = 0;

	if (t->save_ctx != NULL) {
		if (maildir_transaction_save_commit_pre(t->save_ctx) < 0) {
			t->save_ctx = NULL;
			ret = -1;
		}
	}
	if (t->copy_ctx != NULL) {
		if (maildir_transaction_copy_commit(t->copy_ctx) < 0)
			ret = -1;
	}

	save_ctx = t->save_ctx;

	if (index_transaction_commit(_t) < 0)
		ret = -1;

	/* transaction is destroyed. */

	if (save_ctx != NULL) {
		/* unlock uidlist file after writing to transaction log,
		   to make sure we don't write uids in wrong order. */
		maildir_transaction_save_commit_post(save_ctx);
	}

	return ret < 0 ? -1 : maildir_sync_last_commit(mbox);
}

void maildir_transaction_rollback(struct mailbox_transaction_context *_t)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;

	if (t->save_ctx != NULL)
		maildir_transaction_save_rollback(t->save_ctx);
	if (t->copy_ctx != NULL)
		maildir_transaction_copy_rollback(t->copy_ctx);
	index_transaction_rollback(_t);
}
