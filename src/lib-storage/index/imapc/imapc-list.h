#ifndef IMAPC_LIST_H
#define IMAPC_LIST_H

struct imap_arg;

#include "mailbox-list-private.h"

#define MAILBOX_LIST_NAME_IMAPC "imapc"

struct imapc_mailbox_list {
	struct mailbox_list list;
	struct imapc_storage *storage;

	struct mailbox_tree_context *mailboxes, *subscriptions;
	char sep;

	/* we've returned wrong separator. all mailbox list operations must
	   fail from now on. */
	unsigned int broken:1;
};

void imapc_list_register_callbacks(struct imapc_mailbox_list *list);

#endif
