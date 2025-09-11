/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "unichar.h"
#include "imap-match.h"
#include "subscription-file.h"
#include "mailbox-tree.h"
#include "mailbox-list-private.h"
#include "mailbox-list-subscriptions.h"

#include <sys/stat.h>

struct subscriptions_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_tree_context *tree;
	struct mailbox_tree_iterate_context *iter;
	struct mailbox_info info;
};

static int
mailbox_list_subscription_fill_one(struct mailbox_list *list,
				   struct mailbox_list *src_list,
				   const char *name)
{
	struct mail_namespace *ns, *default_ns = list->ns;
	struct mail_namespace *namespaces = default_ns->user->namespaces;
	struct mailbox_node *node;
	const char *vname, *ns_name, *error;
	size_t len;
	bool created;

	/* default_ns is whatever namespace we're currently listing.
	   if we have e.g. prefix="" and prefix=pub/ namespaces with
	   pub/ namespace having subscriptions=no, we want to:

	   1) when listing "" namespace we want to skip over any names
	   that begin with pub/. */
	if (src_list->ns->prefix_len == 0)
		ns_name = name;
	else {
		/* we could have two-level namespace: ns/ns2/ */
		ns_name = t_strconcat(src_list->ns->prefix, name, NULL);
	}
	ns = mail_namespace_find_unsubscribable(namespaces, ns_name);
	if (ns != NULL && ns != default_ns) {
		if (ns->prefix_len > 0)
			return 0;
		/* prefix="" namespace=no : catching this is basically the
		   same as not finding any namespace. */
		ns = NULL;
	}

	/* 2) when listing pub/ namespace, skip over entries that don't
	   begin with pub/. */
	if (ns == NULL &&
	    (default_ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) == 0)
		return 0;

	/* When listing shared namespace's subscriptions, we need to
	   autocreate all the visible child namespaces. their subscriptions
	   are listed later. */
	if (ns != NULL && mail_namespace_is_shared_user_root(ns)) {
		/* we'll need to get the namespace autocreated.
		   one easy way is to just ask to join a reference and
		   pattern */
		(void)mailbox_list_join_refpattern(ns->list, ns_name, "");
		/* If the namespace changes to the newly created one, start
		   the lookup all over again. */
		struct mail_namespace *ns2 =
			mail_namespace_find_unsubscribable(namespaces, ns_name);
		if (ns != ns2)
			return mailbox_list_subscription_fill_one(list, src_list, name);
	}

	/* When listing pub/ namespace, skip over the namespace
	   prefix in the name. the rest of the name is storage_name. */
	if (ns == NULL)
		ns = default_ns;
	else if (strncmp(ns_name, ns->prefix, ns->prefix_len) == 0) {
		ns_name += ns->prefix_len;
		name = ns_name;
	} else {
		/* "pub" entry - this shouldn't be possible normally, because
		   it should be saved as "pub/", but handle it anyway */
		i_assert(strncmp(ns_name, ns->prefix, ns->prefix_len-1) == 0 &&
			 ns_name[ns->prefix_len-1] == '\0');
		name = "";
		/* ns_name = ""; */
	}

	len = strlen(name);
	if (len > 0 && name[len-1] == mail_namespace_get_sep(ns)) {
		/* entry ends with hierarchy separator, remove it.
		   this exists mainly for backwards compatibility with old
		   Dovecot versions and non-Dovecot software that added them */
		name = t_strndup(name, len-1);
	}

	if (!mailbox_list_is_valid_name(list, name, &error)) {
		/* we'll only get into trouble if we show this */
		return -1;
	} else {
		vname = mailbox_list_get_vname(list, name);
		if (!uni_utf8_str_is_valid(vname))
			return -1;
		node = mailbox_tree_get(list->subscriptions, vname, &created);
		node->flags = MAILBOX_SUBSCRIBED;
	}
	return 0;
}

int mailbox_list_subscriptions_refresh(struct mailbox_list *src_list,
				       struct mailbox_list *dest_list)
{
	struct subsfile_list_context *subsfile_ctx;
	struct stat st;
	enum mailbox_list_path_type type;
	const char *path, *name;
	char sep;
	int ret;

	/* src_list is subscriptions=yes, dest_list is subscriptions=no
	   (or the same as src_list) */
	i_assert((src_list->ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) != 0);

	if (dest_list->subscriptions == NULL) {
		sep = mail_namespace_get_sep(src_list->ns);
		dest_list->subscriptions = mailbox_tree_init(sep);
	}

	type = src_list->mail_set->mail_control_path[0] != '\0' ?
		MAILBOX_LIST_PATH_TYPE_CONTROL : MAILBOX_LIST_PATH_TYPE_DIR;
	if (!mailbox_list_get_root_path(src_list, type, &path) ||
	    src_list->mail_set->mailbox_subscriptions_filename[0] == '\0') {
		/* no subscriptions (e.g. pop3c) */
		return 0;
	}
	path = t_strconcat(path, "/",
			   src_list->mail_set->mailbox_subscriptions_filename,
			   NULL);
	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			/* no subscriptions */
			mailbox_tree_clear(dest_list->subscriptions);
			dest_list->subscriptions_mtime = 0;
			return 0;
		}
		mailbox_list_set_critical(dest_list, "stat(%s) failed: %m",
					  path);
		return -1;
	}
	if (st.st_mtime == dest_list->subscriptions_mtime &&
	    st.st_mtime < dest_list->subscriptions_read_time-1) {
		/* we're up to date */
		return 0;
	}

	mailbox_tree_clear(dest_list->subscriptions);
	dest_list->subscriptions_read_time = ioloop_time;

	subsfile_ctx = subsfile_list_init(dest_list, path);
	if (subsfile_list_fstat(subsfile_ctx, &st) == 0)
		dest_list->subscriptions_mtime = st.st_mtime;
	while ((name = subsfile_list_next(subsfile_ctx)) != NULL) T_BEGIN {
		T_BEGIN {
			ret = mailbox_list_subscription_fill_one(dest_list,
								 src_list, name);
		} T_END;
		if (ret < 0) {
			e_warning(dest_list->event,
				  "Subscriptions file %s: "
				  "Removing invalid entry: %s",
				  path, name);
			(void)subsfile_set_subscribed(src_list, path,
				mailbox_list_get_temp_prefix(src_list),
				name, FALSE);

		}
	} T_END;

	if (subsfile_list_deinit(&subsfile_ctx) < 0) {
		dest_list->subscriptions_mtime = (time_t)-1;
		return -1;
	}
	return 0;
}

void mailbox_list_set_subscription_flags(struct mailbox_list *list,
					 const char *vname,
					 enum mailbox_info_flags *flags)
{
	struct mailbox_node *node;

	*flags &= ENUM_NEGATE(MAILBOX_SUBSCRIBED | MAILBOX_CHILD_SUBSCRIBED);

	node = mailbox_tree_lookup(list->subscriptions, vname);
	if (node != NULL) {
		*flags |= node->flags & MAILBOX_SUBSCRIBED;

		/* the only reason why node might have a child is if one of
		   them is subscribed */
		if (node->children != NULL)
			*flags |= MAILBOX_CHILD_SUBSCRIBED;
	}
}

void mailbox_list_subscriptions_fill(struct mailbox_list_iterate_context *ctx,
				     struct mailbox_tree_context *tree)
{
	struct mailbox_list_iter_update_context update_ctx;
	struct mailbox_tree_iterate_context *iter;
	const char *name;

	i_zero(&update_ctx);
	update_ctx.iter_ctx = ctx;
	update_ctx.tree_ctx = tree;
	update_ctx.glob = ctx->glob;
	update_ctx.leaf_flags = MAILBOX_SUBSCRIBED;
	update_ctx.parent_flags = MAILBOX_CHILD_SUBSCRIBED;
	update_ctx.match_parents =
		(ctx->flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0;

	iter = mailbox_tree_iterate_init(ctx->list->subscriptions, NULL,
					 MAILBOX_SUBSCRIBED);
	while (mailbox_tree_iterate_next(iter, &name) != NULL)
		mailbox_list_iter_update(&update_ctx, name);
	mailbox_tree_iterate_deinit(&iter);
}
