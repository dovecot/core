/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

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
	struct subsfile_list_context *subsfile_ctx;
	const char *path, *name;
	string_t *vname;
	bool match_parents;

	vname = t_str_new(256);
	path = t_strconcat(ctx->list->set.control_dir != NULL ?
			   ctx->list->set.control_dir :
			   ctx->list->set.root_dir,
			   "/", ctx->list->set.subscription_fname, NULL);
	subsfile_ctx = subsfile_list_init(ctx->list, path);

	match_parents =
		(ctx->flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0;

	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) {
		name = mail_namespace_get_vname(ns, vname, name);
		mailbox_list_iter_update(ctx, tree_ctx, glob, update_only,
					 match_parents, name);
	}
	return subsfile_list_deinit(subsfile_ctx);
}

int mailbox_list_subscriptions_fill(struct mailbox_list_iterate_context *ctx,
				    struct mailbox_tree_context *tree_ctx,
				    struct imap_match_glob *glob,
				    bool update_only)
{
	int ret;

	T_FRAME(
		ret = mailbox_list_subscriptions_fill_real(ctx, tree_ctx, glob,
							   update_only);
	);
	return ret;
}
