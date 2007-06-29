/* Copyright (C) 2002-2007 Timo Sirainen */

#include "lib.h"
#include "imap-match.h"
#include "mailbox-tree.h"
#include "subscription-file.h"
#include "mailbox-list-private.h"
#include "mailbox-list-subscriptions.h"

static void nodes_add_child_subscribed(struct mailbox_node *node)
{
	while (node != NULL) {
		if (node->children != NULL) {
			node->flags |= MAILBOX_MATCHED |
				MAILBOX_CHILD_SUBSCRIBED;
		}
		node = node->next;
	}
}

int mailbox_list_subscriptions_fill(struct mailbox_list_iterate_context *ctx,
				    struct mailbox_tree_context *tree_ctx,
				    struct imap_match_glob *glob,
				    bool update_only)
{
	struct subsfile_list_context *subsfile_ctx;
	const char *path, *name, *p;
	struct mailbox_node *node;
	char hierarchy_sep;
	bool created, add_flags;

	add_flags = update_only ||
		(ctx->flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0;

	path = t_strconcat(ctx->list->set.control_dir != NULL ?
			   ctx->list->set.control_dir :
			   ctx->list->set.root_dir,
			   "/", ctx->list->set.subscription_fname, NULL);
	subsfile_ctx = subsfile_list_init(ctx->list, path);

	hierarchy_sep = ctx->list->hierarchy_sep;
	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) {
		created = FALSE;
		switch (imap_match(glob, name)) {
		case IMAP_MATCH_YES:
			node = update_only ?
				mailbox_tree_lookup(tree_ctx, name) :
				mailbox_tree_get(tree_ctx, name, &created);
			if (created && add_flags) {
				node->flags = MAILBOX_NONEXISTENT |
					MAILBOX_NOCHILDREN;
			}
			if (node != NULL) {
				if (!update_only)
					node->flags |= MAILBOX_MATCHED;
				node->flags |= MAILBOX_SUBSCRIBED;
			}
			break;
		case IMAP_MATCH_PARENT:
			/* child matched */
			if ((ctx->flags &
			     MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) == 0)
				break;

			while ((p = strrchr(name, hierarchy_sep)) != NULL) {
				name = t_strdup_until(name, p);
				if (imap_match(glob, name) > 0)
					break;
			}
			i_assert(p != NULL);

			node = update_only ?
				mailbox_tree_lookup(tree_ctx, name) :
				mailbox_tree_get(tree_ctx, name, &created);
			if (created && add_flags)
				node->flags = MAILBOX_NONEXISTENT;
			if (node != NULL) {
				if (!update_only)
					node->flags |= MAILBOX_MATCHED;
				node->flags |= MAILBOX_CHILDREN |
					MAILBOX_CHILD_SUBSCRIBED;
				node->flags &= ~MAILBOX_NOCHILDREN;
			}
			break;
		default:
			break;
		}
	}

	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0 &&
	    (ctx->flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0) {
		struct mailbox_node *nodes =
			mailbox_tree_get(tree_ctx, NULL, NULL);

		nodes_add_child_subscribed(nodes);
	}
	return subsfile_list_deinit(subsfile_ctx);
}
