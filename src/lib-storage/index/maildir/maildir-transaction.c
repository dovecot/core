/* Copyright (c) 2004-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "maildir-storage.h"
#include "maildir-sync.h"

static void (*next_hook_mail_index_transaction_created)
	(struct mail_index_transaction *t) = NULL;

static int maildir_transaction_commit(struct mail_index_transaction *t,
				      uint32_t *log_file_seq_r,
				      uoff_t *log_file_offset_r)
{
	struct maildir_transaction_context *mt = MAIL_STORAGE_CONTEXT(t);
	struct maildir_mailbox *mbox = (struct maildir_mailbox *)mt->ictx.ibox;
	struct maildir_save_context *save_ctx;
	bool syncing = t->sync_transaction;
	int ret = 0;

	if (mt->save_ctx != NULL) {
		if (maildir_transaction_save_commit_pre(mt->save_ctx) < 0) {
			mt->save_ctx = NULL;
			ret = -1;
		}
	}

	save_ctx = mt->save_ctx;

	if (ret == 0) {
		if (index_transaction_finish_commit(&mt->ictx, log_file_seq_r,
						    log_file_offset_r) < 0)
			ret = -1;
	} else {
		index_transaction_finish_rollback(&mt->ictx);
	}

	/* transaction is destroyed now. */
	mt = NULL;

	if (save_ctx != NULL)
		maildir_transaction_save_commit_post(save_ctx);

	if (ret == 0 && !syncing)
		ret = maildir_sync_last_commit(mbox);
	return ret;
}

static void maildir_transaction_rollback(struct mail_index_transaction *t)
{
	struct maildir_transaction_context *mt = MAIL_STORAGE_CONTEXT(t);

	if (mt->save_ctx != NULL)
		maildir_transaction_save_rollback(mt->save_ctx);
	index_transaction_finish_rollback(&mt->ictx);
}

static void maildir_transaction_created(struct mail_index_transaction *t)
{
	struct mailbox *box = MAIL_STORAGE_CONTEXT(t->view);

	/* index can be for mailbox list index, in which case box=NULL */
	if (box != NULL &&
	    strcmp(box->storage->name, MAILDIR_STORAGE_NAME) == 0) {
		struct maildir_mailbox *mbox = (struct maildir_mailbox *)box;
		struct maildir_transaction_context *mt;

		mt = i_new(struct maildir_transaction_context, 1);
		mt->ictx.trans = t;
		mt->ictx.super = t->v;

		t->v.commit = maildir_transaction_commit;
		t->v.rollback = maildir_transaction_rollback;
		MODULE_CONTEXT_SET(t, mail_storage_mail_index_module, mt);

		index_transaction_init(&mt->ictx, &mbox->ibox);
	}
	if (next_hook_mail_index_transaction_created != NULL)
		next_hook_mail_index_transaction_created(t);
}

void maildir_transaction_class_init(void)
{
	next_hook_mail_index_transaction_created =
		hook_mail_index_transaction_created;
	hook_mail_index_transaction_created = maildir_transaction_created;
}

void maildir_transaction_class_deinit(void)
{
	i_assert(hook_mail_index_transaction_created ==
		 maildir_transaction_created);
	hook_mail_index_transaction_created =
		next_hook_mail_index_transaction_created;
}
