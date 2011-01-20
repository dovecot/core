/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "subscription-file.h"
#include "mailbox-list-private.h"
#include "mailbox-list-subscriptions.h"

static int
mailbox_list_subscription_fill_one(struct mailbox_list_iter_update_context *update_ctx,
				   struct mail_namespace *default_ns,
				   const char *name)
{
	struct mail_namespace *namespaces = default_ns->user->namespaces;
	struct mail_namespace *ns;
	const char *vname;

	/* default_ns is whatever namespace we're currently listing.
	   if we have e.g. prefix="" and prefix=pub/ namespaces with
	   pub/ namespace having subscriptions=no, we want to:

	   1) when listing "" namespace we want to skip over any names
	   that begin with pub/. */
	ns = mail_namespace_find_unsubscribable(namespaces, name);
	if (ns != NULL && ns != default_ns)
		return 0;

	/* 2) when listing pub/ namespace, skip over entries that don't
	   begin with pub/. */
	if (ns == NULL &&
	    (default_ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) == 0)
		return 0;

	/* When listing shared namespace's subscriptions, we need to
	   autocreate all the visible child namespaces and use the
	   child namespace. */
	if (ns != NULL && ns->type == NAMESPACE_SHARED &&
	    (ns->flags & NAMESPACE_FLAG_AUTOCREATED) == 0) {
		/* we'll need to get the namespace autocreated.
		   one easy way is to just ask if a mailbox name under
		   it is valid, and it gets created */
		(void)mailbox_list_is_valid_existing_name(ns->list, name);
		ns = mail_namespace_find_unsubscribable(namespaces, name);
		i_assert(ns != NULL &&
			 (ns->flags & NAMESPACE_FLAG_AUTOCREATED) != 0);
	}

	/* When listing pub/ namespace, skip over the namespace
	   prefix in the name. the rest of the name is storage_name. */
	if (ns != NULL) {
		i_assert(strncmp(name, ns->prefix, ns->prefix_len) == 0);
		name += ns->prefix_len;
	} else {
		ns = default_ns;
	}

	if (!mailbox_list_is_valid_existing_name(ns->list, name)) {
		/* we'll only get into trouble if we show this */
		return -1;
	} else {
		vname = mailbox_list_get_vname(ns->list, name);
		mailbox_list_iter_update(update_ctx, vname);
	}
	return 0;
}

static int
mailbox_list_subscriptions_fill_real(struct mailbox_list_iterate_context *ctx,
				     struct mailbox_tree_context *tree_ctx,
				     struct imap_match_glob *glob,
				     bool update_only)
{
	struct mail_namespace *ns, *default_ns = ctx->list->ns;
	struct mailbox_list *list = ctx->list;
	struct mailbox_list_iter_update_context update_ctx;
	struct subsfile_list_context *subsfile_ctx;
	const char *path, *name;

	if ((ctx->list->ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) == 0) {
		/* need to list these using another namespace */
		ns = mail_namespace_find_subscribable(default_ns->user->namespaces,
						      default_ns->prefix);
		if (ns == NULL) {
			/* no subscriptions */
			return 0;
		}
		list = ns->list;
	}

	path = t_strconcat(list->set.control_dir != NULL ?
			   list->set.control_dir : list->set.root_dir,
			   "/", list->set.subscription_fname, NULL);
	subsfile_ctx = subsfile_list_init(list, path);

	memset(&update_ctx, 0, sizeof(update_ctx));
	update_ctx.iter_ctx = ctx;
	update_ctx.tree_ctx = tree_ctx;
	update_ctx.glob = glob;
	update_ctx.leaf_flags = MAILBOX_SUBSCRIBED;
	update_ctx.parent_flags = MAILBOX_CHILD_SUBSCRIBED;
	update_ctx.update_only = update_only;
	update_ctx.match_parents =
		(ctx->flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0;

	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) T_BEGIN {
		if (mailbox_list_subscription_fill_one(&update_ctx, default_ns,
						       name) < 0) {
			i_warning("Subscriptions file %s: "
				  "Ignoring invalid entry: %s",
				  path, name);
		}
	} T_END;
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
