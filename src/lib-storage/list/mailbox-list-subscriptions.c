/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

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
	struct mail_namespace *default_ns = ctx->list->ns;
	struct mail_namespace *namespaces = default_ns->user->namespaces;
	struct mailbox_list_iter_update_context update_ctx;
	struct subsfile_list_context *subsfile_ctx;
	struct mail_namespace *ns;
	const char *path, *name, *name2, *full_name, *orig_name;
	string_t *vname;

	vname = str_new(default_pool, 256);
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

	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) T_BEGIN {
		orig_name = name;
		full_name = name2 =
			t_strconcat(default_ns->prefix, name, NULL);
		ns = mail_namespace_find_unsubscribable(namespaces, &name2);
		if (ns == NULL)
			ns = default_ns;
		else if (ns->type == NAMESPACE_SHARED &&
			 (ns->flags & NAMESPACE_FLAG_AUTOCREATED) == 0) {
			/* we'll need to get the namespace autocreated.
			   one easy way is to just ask if a mailbox name under
			   it is valid, and it gets created */
			(void)mailbox_list_is_valid_existing_name(ns->list,
								  name2);
			name = full_name;
			ns = mail_namespace_find_unsubscribable(namespaces,
								&name);
		} else {
			name = name2;
		}

		if (!mailbox_list_is_valid_existing_name(ns->list, name)) {
			/* we'll only get into trouble if we show this */
			i_warning("Subscriptions file %s: "
				  "Removing invalid entry: %s",
				  path, orig_name);
			(void)subsfile_set_subscribed(ns->list, path,
				mailbox_list_get_temp_prefix(ns->list),
				orig_name, FALSE);

		} else {
			name = mail_namespace_get_vname(ns, vname, name);
			mailbox_list_iter_update(&update_ctx, name);
		}
	} T_END;
	str_free(&vname);
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
