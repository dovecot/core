#ifndef __MAILBOX_TREE_H
#define __MAILBOX_TREE_H

#include "mail-storage.h"

struct mailbox_node {
	struct mailbox_node *next;
	struct mailbox_node *children;

	char *name;
	enum mailbox_flags flags;
};

struct mailbox_tree_context *mailbox_tree_init(char separator);
void mailbox_tree_deinit(struct mailbox_tree_context *ctx);

struct mailbox_node *
mailbox_tree_get(struct mailbox_tree_context *ctx, const char *path,
		 int *created);

struct mailbox_node *
mailbox_tree_update(struct mailbox_tree_context *ctx, const char *path);

#endif
