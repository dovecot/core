#ifndef __PROXY_MAILBOX_H
#define __PROXY_MAILBOX_H

#include "mail-storage-private.h"

struct proxy_mailbox {
	struct mailbox proxy_box;
	struct mailbox *box;
};

void proxy_mailbox_init(struct proxy_mailbox *proxy, struct mailbox *box);

#endif
