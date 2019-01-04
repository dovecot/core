/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "virtual-storage.h"
#include "virtual-transaction.h"

struct mailbox_transaction_context *
virtual_transaction_get(struct mailbox_transaction_context *trans,
			struct mailbox *backend_box)
{
	struct virtual_transaction_context *vt =
		(struct virtual_transaction_context *)trans;
	struct mailbox_transaction_context *const *bt, *new_bt;
	unsigned int i, count;

	bt = array_get(&vt->backend_transactions, &count);
	for (i = 0; i < count; i++) {
		if (bt[i]->box == backend_box)
			return bt[i];
	}

	new_bt = mailbox_transaction_begin(backend_box, trans->flags, __func__);
	array_push_back(&vt->backend_transactions, &new_bt);
	return new_bt;
}

struct mailbox_transaction_context *
virtual_transaction_begin(struct mailbox *box,
			  enum mailbox_transaction_flags flags,
			  const char *reason)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	struct virtual_transaction_context *vt;

	vt = i_new(struct virtual_transaction_context, 1);
	i_array_init(&vt->backend_transactions,
		     array_count(&mbox->backend_boxes));
	index_transaction_init(&vt->t, box, flags, reason);
	return &vt->t;
}

int virtual_transaction_commit(struct mailbox_transaction_context *t,
			       struct mail_transaction_commit_changes *changes_r)
{
	struct virtual_transaction_context *vt =
		(struct virtual_transaction_context *)t;
	struct mailbox_transaction_context **bt;
	unsigned int i, count;
	int ret = 0;

	if (t->save_ctx != NULL) {
		virtual_save_free(t->save_ctx);
		t->save_ctx = NULL;
	}

	bt = array_get_modifiable(&vt->backend_transactions, &count);
	for (i = 0; i < count; i++) {
		if (mailbox_transaction_commit(&bt[i]) < 0)
			ret = -1;
	}
	array_free(&vt->backend_transactions);

	if (index_transaction_commit(t, changes_r) < 0)
		ret = -1;
	return ret;
}

void virtual_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct virtual_transaction_context *vt =
		(struct virtual_transaction_context *)t;
	struct mailbox_transaction_context **bt;
	unsigned int i, count;

	if (t->save_ctx != NULL) {
		virtual_save_free(t->save_ctx);
		t->save_ctx = NULL;
	}

	bt = array_get_modifiable(&vt->backend_transactions, &count);
	for (i = 0; i < count; i++)
		mailbox_transaction_rollback(&bt[i]);
	array_free(&vt->backend_transactions);

	index_transaction_rollback(t);
}
