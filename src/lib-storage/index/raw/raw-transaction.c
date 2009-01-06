/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "raw-storage.h"

struct raw_transaction_context {
	struct index_transaction_context ictx;
	union mail_index_transaction_module_context module_ctx;
};

static void (*next_hook_mail_index_transaction_created)
	(struct mail_index_transaction *t) = NULL;

static int
raw_transaction_commit(struct mail_index_transaction *t,
		       uint32_t *log_file_seq_r, uoff_t *log_file_offset_r)
{
	struct raw_transaction_context *mt = MAIL_STORAGE_CONTEXT(t);

	return index_transaction_finish_commit(&mt->ictx, log_file_seq_r,
					       log_file_offset_r);
}

static void raw_transaction_rollback(struct mail_index_transaction *t)
{
	struct raw_transaction_context *mt = MAIL_STORAGE_CONTEXT(t);

	index_transaction_finish_rollback(&mt->ictx);
}

static void raw_transaction_created(struct mail_index_transaction *t)
{
	struct mailbox *box = MAIL_STORAGE_CONTEXT(t->view);

	/* index can be for mailbox list index, in which case box=NULL */
	if (box != NULL &&
	    strcmp(box->storage->name, RAW_STORAGE_NAME) == 0) {
		struct raw_mailbox *raw = (struct raw_mailbox *)box;
		struct raw_transaction_context *mt;

		mt = i_new(struct raw_transaction_context, 1);
		mt->ictx.trans = t;
		mt->ictx.super = t->v;

		t->v.commit = raw_transaction_commit;
		t->v.rollback = raw_transaction_rollback;
		MODULE_CONTEXT_SET(t, mail_storage_mail_index_module, mt);
		index_transaction_init(&mt->ictx, &raw->ibox);
	}

	if (next_hook_mail_index_transaction_created != NULL)
		next_hook_mail_index_transaction_created(t);
}

void raw_transaction_class_init(void)
{
	next_hook_mail_index_transaction_created =
		hook_mail_index_transaction_created;
	hook_mail_index_transaction_created = raw_transaction_created;
}

void raw_transaction_class_deinit(void)
{
	i_assert(hook_mail_index_transaction_created ==
		 raw_transaction_created);
	hook_mail_index_transaction_created =
		next_hook_mail_index_transaction_created;
}
