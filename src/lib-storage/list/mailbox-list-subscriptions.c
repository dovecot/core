/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

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
	bool created, add_matched;

	if ((ctx->list->ns->flags & NAMESPACE_FLAG_INBOX) == 0 ||
	    strcasecmp(name, "INBOX") != 0) {
		/* add namespace prefix to all but INBOX */
		name = t_strconcat(ctx->list->ns->prefix, name, NULL);
	}

	create_flags = (update_only ||
			(ctx->flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0) ?
		(MAILBOX_NONEXISTENT | MAILBOX_NOCHILDREN) : 0;
	always_flags = MAILBOX_SUBSCRIBED;
	add_matched = TRUE;

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
				if (!update_only && add_matched)
					node->flags |= MAILBOX_MATCHED;
				node->flags |= always_flags;
			}
			/* We don't want to show the parent mailboxes unless
			   something else matches them, but if they are matched
			   we want to show them having child subscriptions */
			add_matched = FALSE;
		} else {
			if ((match & IMAP_MATCH_PARENT) == 0)
				break;
			/* We've a (possibly) non-subscribed parent mailbox
			   which has a subscribed child mailbox. Make sure we
			   return the parent mailbox. */
		}

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
		t_push();
		mailbox_list_subscription_add(ctx, tree_ctx, glob, update_only,
					      name);
		t_pop();
	}

	return subsfile_list_deinit(subsfile_ctx);
}
