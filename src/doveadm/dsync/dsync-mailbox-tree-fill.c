/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "guid.h"
#include "str.h"
#include "mailbox-log.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mailbox-list.h"
#include "dsync-mailbox-tree-private.h"

static int
dsync_mailbox_tree_add_node(struct dsync_mailbox_tree *tree,
			    const struct mailbox_info *info,
			    struct dsync_mailbox_node **node_r)
{
	struct dsync_mailbox_node *node;

	node = dsync_mailbox_tree_get(tree, info->vname);
	if (node->ns != info->ns) {
		i_assert(node->ns != NULL);

		i_error("Mailbox '%s' exists in two namespaces: '%s' and '%s'",
			info->vname, node->ns->prefix, info->ns->prefix);
		return -1;
	}
	*node_r = node;
	return 0;
}

static int dsync_mailbox_tree_add(struct dsync_mailbox_tree *tree,
				  const struct mailbox_info *info)
{
	struct dsync_mailbox_node *node;
	struct mailbox *box;
	struct mailbox_metadata metadata;
	struct mailbox_status status;
	const char *errstr;
	enum mail_error error;

	if ((info->flags & MAILBOX_NONEXISTENT) != 0)
		return 0;

	if (dsync_mailbox_tree_add_node(tree, info, &node) < 0)
		return -1;
	node->existence = DSYNC_MAILBOX_NODE_EXISTS;

	if ((info->flags & MAILBOX_NOSELECT) != 0)
		return 0;

	/* get GUID and UIDVALIDITY for selectable mailbox */
	box = mailbox_alloc(info->ns->list, info->vname, 0);
	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0 ||
	    mailbox_get_status(box, STATUS_UIDVALIDITY, &status) < 0) {
		errstr = mailbox_get_last_error(box, &error);
		switch (error) {
		case MAIL_ERROR_NOTFOUND:
			/* mailbox was just deleted? */
			break;
		case MAIL_ERROR_NOTPOSSIBLE:
			/* invalid mbox files? ignore */
			break;
		default:
			i_error("Failed to access mailbox %s: %s",
				info->vname, errstr);
			mailbox_free(&box);
			return -1;
		}
	} else {
		memcpy(node->mailbox_guid, metadata.guid,
		       sizeof(node->mailbox_guid));
		node->uid_validity = status.uidvalidity;
	}
	mailbox_free(&box);
	return 0;
}

static struct dsync_mailbox_node *
dsync_mailbox_tree_find_sha(struct dsync_mailbox_tree *tree,
			    struct mail_namespace *ns, const guid_128_t sha128)
{
	struct dsync_mailbox_node *node;

	if (tree->name128_hash == NULL)
		dsync_mailbox_tree_build_name128_hash(tree);

	node = hash_table_lookup(tree->name128_hash, sha128);
	return node == NULL || node->ns != ns ? NULL : node;
}

static int
dsync_mailbox_tree_add_change_timestamps(struct dsync_mailbox_tree *tree,
					 struct mail_namespace *ns)
{
	struct dsync_mailbox_node *node;
	struct dsync_mailbox_delete *del;
	struct mailbox_log *log;
	struct mailbox_log_iter *iter;
	const struct mailbox_log_record *rec;
	time_t timestamp;

	log = mailbox_list_get_changelog(ns->list);
	if (log == NULL)
		return 0;

	iter = mailbox_log_iter_init(log);
	while ((rec = mailbox_log_iter_next(iter)) != NULL) {
		node = rec->type == MAILBOX_LOG_RECORD_DELETE_MAILBOX ? NULL :
			dsync_mailbox_tree_find_sha(tree, ns, rec->mailbox_guid);

		switch (rec->type) {
		case MAILBOX_LOG_RECORD_DELETE_MAILBOX:
			if (hash_table_lookup(tree->guid_hash,
					      rec->mailbox_guid) != NULL) {
				/* mailbox still exists. maybe it was restored
				   from backup or something. */
				break;
			}
			del = array_append_space(&tree->deletes);
			del->delete_mailbox = TRUE;
			memcpy(del->guid, rec->mailbox_guid, sizeof(del->guid));
			break;
		case MAILBOX_LOG_RECORD_DELETE_DIR:
			if (node != NULL) {
				/* mailbox exists again, skip it */
				break;
			}
			del = array_append_space(&tree->deletes);
			memcpy(del->guid, rec->mailbox_guid, sizeof(del->guid));
			break;
		case MAILBOX_LOG_RECORD_RENAME:
		case MAILBOX_LOG_RECORD_SUBSCRIBE:
		case MAILBOX_LOG_RECORD_UNSUBSCRIBE:
			if (node == NULL)
				break;

			timestamp = mailbox_log_record_get_timestamp(rec);
			if (rec->type == MAILBOX_LOG_RECORD_RENAME)
				node->last_renamed = timestamp;
			else
				node->last_subscription_change = timestamp;
			break;
		}
	}
	if (mailbox_log_iter_deinit(&iter) < 0) {
		i_error("Mailbox log iteration for namespace '%s' failed",
			ns->prefix);
		return -1;
	}
	return 0;
}

int dsync_mailbox_tree_fill(struct dsync_mailbox_tree *tree,
			    struct mail_namespace *ns)
{
	const enum mailbox_list_iter_flags list_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES;
	const enum mailbox_list_iter_flags subs_list_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct mailbox_list_iterate_context *iter;
	struct dsync_mailbox_node *node;
	const struct mailbox_info *info;
	int ret = 0;

	i_assert(mail_namespace_get_sep(ns) == tree->sep);

	/* assign namespace to its root, so it gets copied to children */
	if (ns->prefix_len > 0) {
		node = dsync_mailbox_tree_get(tree,
			t_strndup(ns->prefix, ns->prefix_len-1));
		node->ns = ns;
	} else {
		tree->root.ns = ns;
	}

	/* first add all of the existing mailboxes */
	iter = mailbox_list_iter_init(ns->list, "*", list_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if (dsync_mailbox_tree_add(tree, info) < 0)
			ret = -1;
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		i_error("Mailbox listing for namespace '%s' failed", ns->prefix);
		ret = -1;
	}

	/* add subscriptions */
	iter = mailbox_list_iter_init(ns->list, "*", subs_list_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if (dsync_mailbox_tree_add_node(tree, info, &node) < 0)
			ret = -1;
		else
			node->subscribed = TRUE;
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		i_error("Mailbox listing for namespace '%s' failed", ns->prefix);
		ret = -1;
	}

	if (dsync_mailbox_tree_build_guid_hash(tree) < 0)
		ret = -1;

	/* add timestamps */
	if (dsync_mailbox_tree_add_change_timestamps(tree, ns) < 0)
		ret = -1;
	return ret;
}
