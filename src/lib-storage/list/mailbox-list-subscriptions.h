#ifndef MAILBOX_LIST_SUBSCRIPTIONS_H
#define MAILBOX_LIST_SUBSCRIPTIONS_H

struct mailbox_list_iterate_context;
struct mailbox_tree_context;

int mailbox_list_subscriptions_fill(struct mailbox_list_iterate_context *ctx,
				    struct mailbox_tree_context *tree_ctx,
				    struct imap_match_glob *glob,
				    bool update_only);

#endif
