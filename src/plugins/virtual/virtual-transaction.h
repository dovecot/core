#ifndef VIRTUAL_TRANSACTION_H
#define VIRTUAL_TRANSACTION_H

#include "index-storage.h"

struct virtual_transaction_context {
	struct index_transaction_context ictx;
	union mail_index_transaction_module_context module_ctx;

	struct virtual_save_context *save_ctx;

	ARRAY_DEFINE(backend_transactions,
		     struct mailbox_transaction_context *);
};

struct mailbox_transaction_context *
virtual_transaction_get(struct mailbox_transaction_context *trans,
			struct mailbox *backend_box);

void virtual_transaction_class_init(void);
void virtual_transaction_class_deinit(void);

#endif
