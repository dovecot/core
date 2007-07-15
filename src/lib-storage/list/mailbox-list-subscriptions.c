/* Copyright (C) 2002-2007 Timo Sirainen */

#include "lib.h"
#include "imap-match.h"
#include "mailbox-tree.h"
#include "subscription-file.h"
#include "mailbox-list-private.h"
#include "mailbox-list-subscriptions.h"

static void node_fix_parents(struct mailbox_node *node)
{
	/* If we happened to create any of the parents, we need to mark them
	   nonexistent. */
	node = node->parent;
	for (; node != NULL; node = node->parent) {
		if ((node->flags & MAILBOX_MATCHED) == 0)
			node->flags |= MAILBOX_NONEXISTENT;
	}
}

static void
mailbox_list_subscription_add(struct mailbox_list_iterate_context *ctx,
			      struct mailbox_tree_context *tree_ctx,
			      struct imap_match_glob *glob,
			      bool update_only, const char *name)
{
	struct mailbox_node *node;
	enum mailbox_info_flags create_flags, always_flags;
	enum imap_match_result match;
	const char *p;
	bool created;

	create_flags = (update_only ||
			(ctx->flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0) ?
		(MAILBOX_NONEXISTENT | MAILBOX_NOCHILDREN) : 0;
	always_flags = MAILBOX_SUBSCRIBED;

	t_push();
	for (;;) {
		created = FALSE;
		match = imap_match(glob, name);
		if (match == IMAP_MATCH_YES) {
			node = update_only ?
				mailbox_tree_lookup(tree_ctx, name) :
				mailbox_tree_get(tree_ctx, name, &created);
			if (created) {
				node->flags = create_flags;
				if (create_flags != 0)
					node_fix_parents(node);
			}
			if (node != NULL) {
				if (!update_only)
					node->flags |= MAILBOX_MATCHED;
				node->flags |= always_flags;
			}
		} else if ((match & IMAP_MATCH_PARENT) == 0)
			break;

		if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) == 0)
			break;

		/* see if parent matches */
		p = strrchr(name, ctx->list->hierarchy_sep);
		if (p == NULL)
			break;

		name = t_strdup_until(name, p);
		create_flags &= ~MAILBOX_NOCHILDREN;
		always_flags = MAILBOX_CHILDREN | MAILBOX_CHILD_SUBSCRIBED;
	}
	t_pop();
}

int mailbox_list_subscriptions_fill(struct mailbox_list_iterate_context *ctx,
				    struct mailbox_tree_context *tree_ctx,
				    struct imap_match_glob *glob,
				    bool update_only)
{
	struct subsfile_list_context *subsfile_ctx;
	const char *path, *name;

	path = t_strconcat(ctx->list->set.control_dir != NULL ?
			   ctx->list->set.control_dir :
			   ctx->list->set.root_dir,
			   "/", ctx->list->set.subscription_fname, NULL);
	subsfile_ctx = subsfile_list_init(ctx->list, path);

	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) {
		mailbox_list_subscription_add(ctx, tree_ctx, glob, update_only,
					      name);
	}

	return subsfile_list_deinit(subsfile_ctx);
}
