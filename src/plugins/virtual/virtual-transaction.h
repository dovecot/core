#ifndef VIRTUAL_TRANSACTION_H
#define VIRTUAL_TRANSACTION_H

#include "index-storage.h"

struct virtual_transaction_context {
	struct mailbox_transaction_context t;

	ARRAY(struct mailbox_transaction_context *) backend_transactions;
};

struct mailbox_transaction_context *
virtual_transaction_get(struct mailbox_transaction_context *trans,
			struct mailbox *backend_box);

struct mailbox_transaction_context *
virtual_transaction_begin(struct mailbox *box,
			  enum mailbox_transaction_flags flags);
int virtual_transaction_commit(struct mailbox_transaction_context *t,
			       struct mail_transaction_commit_changes *changes_r);
void virtual_transaction_rollback(struct mailbox_transaction_context *t);

#endif
