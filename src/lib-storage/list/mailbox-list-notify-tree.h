#ifndef MAILBOX_LIST_NOTIFY_TREE_H
#define MAILBOX_LIST_NOTIFY_TREE_H

#include "mailbox-tree.h"

struct mailbox_notify_node {
	struct mailbox_node node;

	guid_128_t guid;
	uint32_t index_uid;

	uint32_t uidvalidity;
	uint32_t uidnext;
	uint32_t messages;
	uint32_t unseen;
	uint64_t highest_modseq;
};

struct mailbox_list_notify_tree *
mailbox_list_notify_tree_init(struct mailbox_list *list);
void mailbox_list_notify_tree_deinit(struct mailbox_list_notify_tree **tree);

struct mailbox_notify_node *
mailbox_list_notify_tree_lookup(struct mailbox_list_notify_tree *tree,
				const char *storage_name);

#endif
