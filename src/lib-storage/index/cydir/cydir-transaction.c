/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "cydir-sync.h"
#include "cydir-storage.h"

static void (*next_hook_mail_index_transaction_created)
	(struct mail_index_transaction *t) = NULL;

static int cydir_transaction_commit(struct mail_index_transaction *t,
				    uint32_t *log_file_seq_r,
				    uoff_t *log_file_offset_r)
{
	struct cydir_transaction_context *dt = MAIL_STORAGE_CONTEXT(t);
	struct cydir_mailbox *mbox = (struct cydir_mailbox *)dt->ictx.ibox;
	struct cydir_save_context *save_ctx;
	bool syncing = t->sync_transaction;
	int ret = 0;

	if (dt->save_ctx != NULL) {
		if (cydir_transaction_save_commit_pre(dt->save_ctx) < 0) {
			dt->save_ctx = NULL;
			ret = -1;
		}
	}

	save_ctx = dt->save_ctx;

	if (ret < 0)
		index_transaction_finish_rollback(&dt->ictx);
	else {
		if (index_transaction_finish_commit(&dt->ictx, log_file_seq_r,
						    log_file_offset_r) < 0)
			ret = -1;
	}

	/* transaction is destroyed now. */
	dt = NULL;

	if (save_ctx != NULL) {
		/* unlock uidlist file after writing to transaction log,
		   to make sure we don't write uids in wrong order. */
		cydir_transaction_save_commit_post(save_ctx);
	}

	if (ret == 0 && !syncing) {
		if (cydir_sync(mbox) < 0)
			ret = -1;
	}

	return ret;
}

static void cydir_transaction_rollback(struct mail_index_transaction *t)
{
	struct cydir_transaction_context *dt = MAIL_STORAGE_CONTEXT(t);

	if (dt->save_ctx != NULL)
		cydir_transaction_save_rollback(dt->save_ctx);

	index_transaction_finish_rollback(&dt->ictx);
}

static void cydir_transaction_created(struct mail_index_transaction *t)
{
	struct mailbox *box = MAIL_STORAGE_CONTEXT(t->view);

	/* index can be for mailbox list index, in which case box=NULL */
	if (box != NULL &&
	    strcmp(box->storage->name, CYDIR_STORAGE_NAME) == 0) {
		struct cydir_mailbox *cydir = (struct cydir_mailbox *)box;
		struct cydir_transaction_context *mt;

		mt = i_new(struct cydir_transaction_context, 1);
		mt->ictx.trans = t;
		mt->ictx.super = t->v;

		t->v.commit = cydir_transaction_commit;
		t->v.rollback = cydir_transaction_rollback;
		MODULE_CONTEXT_SET(t, mail_storage_mail_index_module, mt);

		index_transaction_init(&mt->ictx, &cydir->ibox);
	}

	if (next_hook_mail_index_transaction_created != NULL)
		next_hook_mail_index_transaction_created(t);
}

void cydir_transaction_class_init(void)
{
	next_hook_mail_index_transaction_created =
		hook_mail_index_transaction_created;
	hook_mail_index_transaction_created = cydir_transaction_created;
}

void cydir_transaction_class_deinit(void)
{
	i_assert(hook_mail_index_transaction_created ==
		 cydir_transaction_created);
	hook_mail_index_transaction_created =
		next_hook_mail_index_transaction_created;
}
