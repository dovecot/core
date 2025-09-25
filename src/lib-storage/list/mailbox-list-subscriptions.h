#ifndef MAILBOX_LIST_SUBSCRIPTIONS_H
#define MAILBOX_LIST_SUBSCRIPTIONS_H

#include "mailbox-list-iter.h"

struct mailbox_tree_context;
struct mailbox_list_iterate_context;

int mailbox_list_subscriptions_refresh(struct mailbox_list *src_list,
				       struct mailbox_list *dest_list);

/* Add subscriptions matching the iteration to the given tree */
void mailbox_list_subscriptions_fill(struct mailbox_list_iterate_context *ctx,
				     struct mailbox_tree_context *tree);

#endif
