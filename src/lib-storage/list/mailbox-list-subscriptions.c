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

static void
mailbox_list_subscriptions_apply_nfc_renames(struct mailbox_list *src_list,
					     struct mailbox_list *dest_list,
					     const char *path,
					     const ARRAY_TYPE(const_string) *renames)
{
	const char *const *names;
	unsigned int i, count;
	const char *temp_prefix = mailbox_list_get_temp_prefix(src_list);

	names = array_get(renames, &count);
	for (i = 0; i < count; i += 2) {
		const char *old_name = names[i];
		const char *new_name = names[i + 1];

		/* Add the NFC name first so a crash between the two
		   operations leaves the subscription intact (just under
		   the non-NFC name, which a later refresh will retry). */
		if (subsfile_set_subscribed(src_list, path, temp_prefix,
					    new_name, TRUE) < 0) {
			mailbox_list_set_critical(dest_list,
				"Failed to add NFC-normalized subscription "
				"'%s' to %s: %s", new_name, path,
				mailbox_list_get_last_internal_error(src_list,
								     NULL));
			break;
		}
		if (subsfile_set_subscribed(src_list, path, temp_prefix,
					    old_name, FALSE) < 0) {
			mailbox_list_set_critical(dest_list,
				"Failed to remove non-NFC subscription '%s' "
				"from %s: %s", old_name, path,
				mailbox_list_get_last_internal_error(src_list,
								     NULL));
			break;
		}
		e_debug(dest_list->event,
			"Subscription '%s' renamed to '%s' "
			"for NFC normalization", old_name, new_name);
	}
	/* The file mtime changed; invalidate so a subsequent read re-stats
	   but tree state is already correct. */
	dest_list->subscriptions_mtime = (time_t)-1;
}

int mailbox_list_subscriptions_refresh(struct mailbox_list *src_list,
				       struct mailbox_list *dest_list)
{
	struct subsfile_list_context *subsfile_ctx;
	struct stat st;
	enum mailbox_list_path_type type;
	const char *path, *name;
	char sep;
	bool nfc = src_list->mail_set->mailbox_list_normalize_names_to_nfc;
	ARRAY_TYPE(const_string) nfc_renames = ARRAY_INIT;
	pool_t nfc_pool = NULL;

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
		const char *nfc_name = name;
		bool change_to_nfc = FALSE;

		if (nfc) {
			int nfc_ret = uni_utf8_to_nfc(name, strlen(name),
						      &nfc_name);
			if (nfc_ret >= 0 && strcmp(name, nfc_name) != 0)
				change_to_nfc = TRUE;
			else
				nfc_name = name;
		}
		if (mailbox_list_subscription_fill_one(dest_list, src_list,
						       nfc_name) < 0) {
			e_warning(dest_list->event,
				  "Subscriptions file %s: "
				  "Removing invalid entry: %s",
				  path, name);
			(void)subsfile_set_subscribed(src_list, path,
				mailbox_list_get_temp_prefix(src_list),
				name, FALSE);

		} else if (change_to_nfc) {
			/* The on-disk subscription name was not in NFC form.
			   Remember to rewrite it after we're done reading. */
			if (nfc_pool == NULL) {
				nfc_pool = pool_alloconly_create(
					"subscriptions nfc renames", 256);
				p_array_init(&nfc_renames, nfc_pool, 4);
			}
			const char *old_name_dup = p_strdup(nfc_pool, name);
			const char *new_name_dup = p_strdup(nfc_pool, nfc_name);
			array_push_back(&nfc_renames, &old_name_dup);
			array_push_back(&nfc_renames, &new_name_dup);
		}
	} T_END;

	if (subsfile_list_deinit(&subsfile_ctx) < 0) {
		dest_list->subscriptions_mtime = (time_t)-1;
		pool_unref(&nfc_pool);
		return -1;
	}

	if (array_not_empty(&nfc_renames)) {
		mailbox_list_subscriptions_apply_nfc_renames(
			src_list, dest_list, path, &nfc_renames);
	}
	pool_unref(&nfc_pool);
	return 0;
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
