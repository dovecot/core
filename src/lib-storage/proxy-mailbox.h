#ifndef __PROXY_MAILBOX_H
#define __PROXY_MAILBOX_H

#include "mail-storage-private.h"

struct proxy_mailbox {
	struct mailbox proxy_box;
	struct mailbox *box;
};

struct proxy_mailbox_transaction_context {
	struct mailbox_transaction_context proxy_ctx;
	struct mailbox_transaction_context *ctx;
};

void proxy_mailbox_init(struct proxy_mailbox *proxy_box, struct mailbox *box);
void proxy_transaction_init(struct proxy_mailbox *proxy_box,
			    struct proxy_mailbox_transaction_context *proxy_ctx,
                            struct mailbox_transaction_context *ctx);

#endif
