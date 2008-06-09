/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "subscription-file.h"
#include "mailbox-list-private.h"
#include "mailbox-list-subscriptions.h"

static int
mailbox_list_subscriptions_fill_real(struct mailbox_list_iterate_context *ctx,
				     struct mailbox_tree_context *tree_ctx,
				     struct imap_match_glob *glob,
				     bool update_only)
{
	struct mail_namespace *ns = ctx->list->ns;
	struct mailbox_list_iter_update_context update_ctx;
	struct subsfile_list_context *subsfile_ctx;
	const char *path, *name;
	string_t *vname;

	vname = t_str_new(256);
	path = t_strconcat(ctx->list->set.control_dir != NULL ?
			   ctx->list->set.control_dir :
			   ctx->list->set.root_dir,
			   "/", ctx->list->set.subscription_fname, NULL);
	subsfile_ctx = subsfile_list_init(ctx->list, path);

	memset(&update_ctx, 0, sizeof(update_ctx));
	update_ctx.iter_ctx = ctx;
	update_ctx.tree_ctx = tree_ctx;
	update_ctx.glob = glob;
	update_ctx.leaf_flags = MAILBOX_SUBSCRIBED;
	update_ctx.parent_flags = MAILBOX_CHILD_SUBSCRIBED;
	update_ctx.update_only = update_only;
	update_ctx.match_parents =
		(ctx->flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0;

	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) {
		name = mail_namespace_get_vname(ns, vname, name);
		mailbox_list_iter_update(&update_ctx, name);
	}
	return subsfile_list_deinit(subsfile_ctx);
}

int mailbox_list_subscriptions_fill(struct mailbox_list_iterate_context *ctx,
				    struct mailbox_tree_context *tree_ctx,
				    struct imap_match_glob *glob,
				    bool update_only)
{
	int ret;

	T_BEGIN {
		ret = mailbox_list_subscriptions_fill_real(ctx, tree_ctx, glob,
							   update_only);
	} T_END;
	return ret;
}
