/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "maildir-storage.h"

struct mailbox_transaction_context *
maildir_transaction_begin(struct mailbox *box, int hide)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct maildir_transaction_context *ctx;

	ctx = i_new(struct maildir_transaction_context, 1);
	ctx->ictx.mailbox_ctx.box = box;
	ctx->ictx.ibox = ibox;
	ctx->ictx.trans = mail_index_transaction_begin(ibox->view, hide);
	return &ctx->ictx.mailbox_ctx;
}

int maildir_transaction_commit(struct mailbox_transaction_context *_t)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;
	struct index_mailbox *ibox = t->ictx.ibox;
	int ret = 0;

	if (t->save_ctx != NULL) {
		if (maildir_save_commit(t->save_ctx) < 0)
			ret = -1;
	}
	if (t->copy_ctx != NULL) {
		if (maildir_copy_commit(t->copy_ctx) < 0)
			ret = -1;
	}

	if (index_transaction_commit(_t) < 0)
		return -1;

	return ret < 0 ? -1 : maildir_sync_last_commit(ibox);
}

void maildir_transaction_rollback(struct mailbox_transaction_context *_t)
{
	struct maildir_transaction_context *t =
		(struct maildir_transaction_context *)_t;

	if (t->save_ctx != NULL)
		maildir_save_rollback(t->save_ctx);
	if (t->copy_ctx != NULL)
		maildir_copy_rollback(t->copy_ctx);
	index_transaction_rollback(_t);
}
