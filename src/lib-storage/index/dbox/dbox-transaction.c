/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "dbox-storage.h"
#include "dbox-sync.h"

static void (*next_hook_mail_index_transaction_created)
	(struct mail_index_transaction *t) = NULL;

static int dbox_transaction_commit(struct mail_index_transaction *t,
				   uint32_t *log_file_seq_r,
				   uoff_t *log_file_offset_r)
{
	struct dbox_transaction_context *dt = MAIL_STORAGE_CONTEXT(t);
	struct dbox_save_context *save_ctx;
	int ret = 0;

	if (dt->save_ctx != NULL) {
		if (dbox_transaction_save_commit_pre(dt->save_ctx) < 0) {
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
		dbox_transaction_save_commit_post(save_ctx);
	}
	return ret;
}

static void dbox_transaction_rollback(struct mail_index_transaction *t)
{
	struct dbox_transaction_context *dt = MAIL_STORAGE_CONTEXT(t);

	if (dt->save_ctx != NULL)
		dbox_transaction_save_rollback(dt->save_ctx);

	index_transaction_finish_rollback(&dt->ictx);
}

static void dbox_transaction_created(struct mail_index_transaction *t)
{
	struct mailbox *box = MAIL_STORAGE_CONTEXT(t->view);

	/* index can be for mailbox list index, in which case box=NULL */
	if (box != NULL &&
	    strcmp(box->storage->name, DBOX_STORAGE_NAME) == 0) {
		struct dbox_mailbox *dbox = (struct dbox_mailbox *)box;
		struct dbox_transaction_context *mt;

		mt = i_new(struct dbox_transaction_context, 1);
		mt->ictx.trans = t;
		mt->ictx.super = t->v;

		t->v.commit = dbox_transaction_commit;
		t->v.rollback = dbox_transaction_rollback;
		MODULE_CONTEXT_SET(t, mail_storage_mail_index_module, mt);

		index_transaction_init(&mt->ictx, &dbox->ibox);
	}

	if (next_hook_mail_index_transaction_created != NULL)
		next_hook_mail_index_transaction_created(t);
}

void dbox_transaction_class_init(void)
{
	next_hook_mail_index_transaction_created =
		hook_mail_index_transaction_created;
	hook_mail_index_transaction_created = dbox_transaction_created;
}

void dbox_transaction_class_deinit(void)
{
	i_assert(hook_mail_index_transaction_created ==
		 dbox_transaction_created);
	hook_mail_index_transaction_created =
		next_hook_mail_index_transaction_created;
}
