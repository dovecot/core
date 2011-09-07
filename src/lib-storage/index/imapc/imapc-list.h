#ifndef IMAPC_LIST_H
#define IMAPC_LIST_H

struct imap_arg;

#include "mailbox-list-private.h"

#define MAILBOX_LIST_NAME_IMAPC "imapc"

struct imapc_mailbox_list {
	struct mailbox_list list;
	struct imapc_storage *storage;
	struct mailbox_list *index_list;

	struct mailbox_tree_context *mailboxes, *tmp_subscriptions;
	char sep;

	unsigned int iter_count;

	unsigned int refreshed_subscriptions:1;
	unsigned int refreshed_mailboxes:1;
	unsigned int index_list_failed:1;
};

void imapc_list_register_callbacks(struct imapc_mailbox_list *list);

#endif
