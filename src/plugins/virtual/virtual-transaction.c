/* Copyright (c) 2008-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "virtual-storage.h"
#include "virtual-transaction.h"

static void (*next_hook_mail_index_transaction_created)
	(struct mail_index_transaction *t) = NULL;

struct mailbox_transaction_context *
virtual_transaction_get(struct mailbox_transaction_context *trans,
			struct mailbox *backend_box)
{
	struct virtual_transaction_context *dt =
		(struct virtual_transaction_context *)trans;
	struct mailbox_transaction_context *const *bt, *new_bt;
	unsigned int i, count;

	bt = array_get(&dt->backend_transactions, &count);
	for (i = 0; i < count; i++) {
		if (bt[i]->box == backend_box)
			return bt[i];
	}

	new_bt = mailbox_transaction_begin(backend_box, trans->flags);
	array_append(&dt->backend_transactions, &new_bt, 1);
	return new_bt;
}

static int virtual_transaction_commit(struct mail_index_transaction *t,
				      uint32_t *log_file_seq_r,
				      uoff_t *log_file_offset_r)
{
	struct virtual_transaction_context *dt = MAIL_STORAGE_CONTEXT(t);
	struct mailbox_transaction_context **bt;
	unsigned int i, count;
	int ret = 0;

	if (dt->save_ctx != NULL)
		virtual_save_free(dt->save_ctx);

	bt = array_get_modifiable(&dt->backend_transactions, &count);
	for (i = 0; i < count; i++) {
		if (mailbox_transaction_commit(&bt[i]) < 0)
			ret = -1;
	}
	array_free(&dt->backend_transactions);

	if (index_transaction_finish_commit(&dt->ictx, log_file_seq_r,
					    log_file_offset_r) < 0)
		ret = -1;
	return ret;
}

static void virtual_transaction_rollback(struct mail_index_transaction *t)
{
	struct virtual_transaction_context *dt = MAIL_STORAGE_CONTEXT(t);
	struct mailbox_transaction_context **bt;
	unsigned int i, count;

	if (dt->save_ctx != NULL)
		virtual_save_free(dt->save_ctx);

	bt = array_get_modifiable(&dt->backend_transactions, &count);
	for (i = 0; i < count; i++)
		mailbox_transaction_rollback(&bt[i]);
	array_free(&dt->backend_transactions);

	index_transaction_finish_rollback(&dt->ictx);
}

static void virtual_transaction_created(struct mail_index_transaction *t)
{
	struct mailbox *box = MAIL_STORAGE_CONTEXT(t->view);

	/* index can be for mailbox list index, in which case box=NULL */
	if (box != NULL &&
	    strcmp(box->storage->name, VIRTUAL_STORAGE_NAME) == 0) {
		struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
		struct virtual_transaction_context *mt;

		mt = i_new(struct virtual_transaction_context, 1);
		mt->ictx.trans = t;
		mt->ictx.super = t->v;

		t->v.commit = virtual_transaction_commit;
		t->v.rollback = virtual_transaction_rollback;
		MODULE_CONTEXT_SET(t, mail_storage_mail_index_module, mt);

		i_array_init(&mt->backend_transactions,
			     array_count(&mbox->backend_boxes));
		index_transaction_init(&mt->ictx, &mbox->ibox);
	}

	if (next_hook_mail_index_transaction_created != NULL)
		next_hook_mail_index_transaction_created(t);
}

void virtual_transaction_class_init(void)
{
	next_hook_mail_index_transaction_created =
		hook_mail_index_transaction_created;
	hook_mail_index_transaction_created = virtual_transaction_created;
}

void virtual_transaction_class_deinit(void)
{
	i_assert(hook_mail_index_transaction_created ==
		 virtual_transaction_created);
	hook_mail_index_transaction_created =
		next_hook_mail_index_transaction_created;
}
