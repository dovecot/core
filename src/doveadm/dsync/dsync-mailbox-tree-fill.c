/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "guid.h"
#include "str.h"
#include "wildcard-match.h"
#include "mailbox-log.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mailbox-list-iter.h"
#include "dsync-brain.h"
#include "dsync-mailbox-tree-private.h"

static const char *
dsync_mailbox_tree_name_unescape(struct mail_namespace *ns,
				 const char *old_vname, char alt_char)
{
	const char ns_sep = mail_namespace_get_sep(ns);
	const char escape_char =
		ns->list->mail_set->mailbox_list_visible_escape_char[0];
	const char *const *old_vname_parts =
		dsync_mailbox_name_to_parts(old_vname, ns_sep, escape_char);

	string_t *new_vname = t_str_new(128);
	for (; *old_vname_parts != NULL; old_vname_parts++) {
		for (const char *p = *old_vname_parts; *p != '\0'; p++) {
			if (*p != ns_sep)
				str_append_c(new_vname, *p);
			else
				str_append_c(new_vname, alt_char);
		}
		str_append_c(new_vname, ns_sep);
	}
	str_truncate(new_vname, str_len(new_vname)-1);
	return str_c(new_vname);
};

static int
dsync_mailbox_tree_add_node(struct dsync_mailbox_tree *tree,
			    const struct mailbox_info *info,
			    char alt_char, struct event *event,
			    struct dsync_mailbox_node **node_r)
{
	struct dsync_mailbox_node *node;
	const char *vname = info->vname;

	struct dsync_mailbox_list *dlist = DSYNC_LIST_CONTEXT(info->ns->list);
	if (dlist != NULL && !dlist->have_orig_escape_char) {
		/* The escape character was added only for dsync internally.
		   Normally there is no escape character configured. Change
		   the mailbox names so that it doesn't rely on it. */
		vname = dsync_mailbox_tree_name_unescape(info->ns, vname, alt_char);
	}

	node = dsync_mailbox_tree_get(tree, vname);
	if (node->ns == info->ns)
		;
	else if (node->ns == NULL) {
		i_assert(tree->root.ns == NULL);
		node->ns = info->ns;
	} else {
		e_error(event,
			"Mailbox '%s' exists in two namespaces: %s and %s",
			vname, node->ns->set->name, info->ns->set->name);
		return -1;
	}
	*node_r = node;
	return 0;
}

static int
dsync_mailbox_tree_add_exists_node(struct dsync_mailbox_tree *tree,
				   const struct mailbox_info *info,
				   struct dsync_mailbox_node **node_r,
				   char alt_char, struct event *event,
				   enum mail_error *error_r)
{
	if (dsync_mailbox_tree_add_node(tree, info, alt_char, event, node_r) < 0) {
		*error_r = MAIL_ERROR_TEMP;
		return -1;
	}
	(*node_r)->existence = DSYNC_MAILBOX_NODE_EXISTS;
	return 0;
}

static int
dsync_mailbox_tree_get_selectable(struct mailbox *box,
				  struct mailbox_metadata *metadata_r,
				  struct mailbox_status *status_r)
{
	/* try the fast path */
	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, metadata_r) < 0)
		return -1;
	if (mailbox_get_status(box, STATUS_UIDVALIDITY | STATUS_UIDNEXT, status_r) < 0)
		return -1;

	i_assert(!guid_128_is_empty(metadata_r->guid));
	if (status_r->uidvalidity != 0)
		return 0;

	/* no UIDVALIDITY assigned yet. syncing a mailbox should add it. */
	if (mailbox_sync(box, 0) < 0)
		return -1;
	if (mailbox_get_status(box, STATUS_UIDVALIDITY | STATUS_UIDNEXT, status_r) < 0)
		return -1;
	i_assert(status_r->uidvalidity != 0);
	return 0;
}

static int dsync_mailbox_tree_add(struct dsync_mailbox_tree *tree,
				  const struct mailbox_info *info,
				  const guid_128_t box_guid,
				  char alt_char, struct event *event,
				  enum mail_error *error_r)
{
	struct dsync_mailbox_node *node;
	struct mailbox *box;
	enum mailbox_existence existence;
	struct mailbox_metadata metadata;
	struct mailbox_status status;
	const char *errstr;
	enum mail_error error;
	int ret = 0;

	if ((info->flags & MAILBOX_NONEXISTENT) != 0)
		return 0;
	if ((info->flags & MAILBOX_NOSELECT) != 0) {
		return !guid_128_is_empty(box_guid) ? 0 :
			dsync_mailbox_tree_add_exists_node(
				tree, info, &node, alt_char, event, error_r);
	}

	/* get GUID and UIDVALIDITY for selectable mailbox */
	box = mailbox_alloc(info->ns->list, info->vname, MAILBOX_FLAG_READONLY);
	ret = mailbox_exists(box, FALSE, &existence);
	if (ret == 0 && existence != MAILBOX_EXISTENCE_SELECT) {
		/* autocreated mailbox doesn't exist yet */
		mailbox_free(&box);
		if (existence == MAILBOX_EXISTENCE_NOSELECT) {
			return !guid_128_is_empty(box_guid) ? 0 :
				dsync_mailbox_tree_add_exists_node(
					tree, info, &node, alt_char, event, error_r);
		} else {
			return 0;
		}
	}
	i_assert(ret <= 0);
	if (ret == 0)
		ret = dsync_mailbox_tree_get_selectable(box, &metadata, &status);
	if (ret < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		ret = 0;
		switch (error) {
		case MAIL_ERROR_NOTFOUND:
			/* mailbox was just deleted? */
			break;
		case MAIL_ERROR_NOTPOSSIBLE:
			/* invalid mbox files? ignore */
			break;
		default:
			e_error(event, "Failed to access mailbox %s: %s",
				info->vname, errstr);
			*error_r = error;
			ret = -1;
		}
		mailbox_free(&box);
		return ret;
	}
	mailbox_free(&box);

	if (!guid_128_is_empty(box_guid) &&
	    !guid_128_equals(box_guid, metadata.guid)) {
		/* unwanted mailbox */
		return 0;
	}
	if (dsync_mailbox_tree_add_exists_node(
		tree, info, &node, alt_char, event, error_r) < 0)
		return -1;
	memcpy(node->mailbox_guid, metadata.guid,
	       sizeof(node->mailbox_guid));
	node->uid_validity = status.uidvalidity;
	node->uid_next = status.uidnext;
	return 0;
}

static struct dsync_mailbox_node *
dsync_mailbox_tree_find_sha(struct dsync_mailbox_tree *tree,
			    struct mail_namespace *ns, const guid_128_t sha128)
{
	struct dsync_mailbox_node *node;

	if (!hash_table_is_created(tree->name128_hash))
		dsync_mailbox_tree_build_name128_hash(tree);

	node = hash_table_lookup(tree->name128_hash, sha128);
	return node == NULL || node->ns != ns ? NULL : node;
}

static int
dsync_mailbox_tree_add_change_timestamps(struct dsync_mailbox_tree *tree,
					 struct mail_namespace *ns,
					 struct event *event)
{
	struct dsync_mailbox_node *node;
	struct dsync_mailbox_delete *del;
	struct mailbox_log *log;
	struct mailbox_log_iter *iter;
	const struct mailbox_log_record *rec;
	const uint8_t *guid_p;
	time_t timestamp;

	log = mailbox_list_get_changelog(ns->list);
	if (log == NULL)
		return 0;

	iter = mailbox_log_iter_init(log);
	while ((rec = mailbox_log_iter_next(iter)) != NULL) {
		/* For DELETE_MAILBOX the record_guid is the mailbox GUID.
		   Otherwise it's 128bit SHA1 of the mailbox vname. */
		node = rec->type == MAILBOX_LOG_RECORD_DELETE_MAILBOX ? NULL :
			dsync_mailbox_tree_find_sha(tree, ns, rec->mailbox_guid);

		timestamp = mailbox_log_record_get_timestamp(rec);
		switch (rec->type) {
		case MAILBOX_LOG_RECORD_DELETE_MAILBOX:
			guid_p = rec->mailbox_guid;
			if (hash_table_lookup(tree->guid_hash, guid_p) != NULL) {
				/* mailbox still exists. maybe it was restored
				   from backup or something. */
				break;
			}
			del = array_append_space(&tree->deletes);
			del->type = DSYNC_MAILBOX_DELETE_TYPE_MAILBOX;
			del->timestamp = timestamp;
			memcpy(del->guid, rec->mailbox_guid, sizeof(del->guid));
			break;
		case MAILBOX_LOG_RECORD_DELETE_DIR:
			if (node != NULL &&
			    node->existence == DSYNC_MAILBOX_NODE_EXISTS) {
				/* directory exists again, skip it */
				break;
			}
			/* we don't know what directory name was deleted,
			   just its hash. if the name still exists on the other
			   dsync side, it can match this deletion to the
			   name. */
			del = array_append_space(&tree->deletes);
			del->type = DSYNC_MAILBOX_DELETE_TYPE_DIR;
			del->timestamp = timestamp;
			memcpy(del->guid, rec->mailbox_guid, sizeof(del->guid));
			break;
		case MAILBOX_LOG_RECORD_CREATE_DIR:
			if (node == NULL) {
				/* directory has been deleted again, skip it */
				break;
			}
			/* notify the remote that we want to keep this
			   directory created (unless remote has a newer delete
			   timestamp) */
			node->last_renamed_or_created = timestamp;
			break;
		case MAILBOX_LOG_RECORD_RENAME:
			if (node != NULL)
				node->last_renamed_or_created = timestamp;
			break;
		case MAILBOX_LOG_RECORD_SUBSCRIBE:
			if (node != NULL)
				node->last_subscription_change = timestamp;
			break;
		case MAILBOX_LOG_RECORD_UNSUBSCRIBE:
			if (node != NULL) {
				node->last_subscription_change = timestamp;
				break;
			}
			/* The mailbox is already deleted, but it may still
			   exist on the other side (even the subscription
			   alone). */
			del = array_append_space(&tree->deletes);
			del->type = DSYNC_MAILBOX_DELETE_TYPE_UNSUBSCRIBE;
			del->timestamp = timestamp;
			memcpy(del->guid, rec->mailbox_guid, sizeof(del->guid));
			break;
		}
	}
	if (mailbox_log_iter_deinit(&iter) < 0) {
		e_error(event, "Mailbox log iteration for namespace %s failed",
			ns->set->name);
		return -1;
	}
	return 0;
}

static int
dsync_mailbox_tree_fix_guid_duplicate(struct dsync_mailbox_tree *tree,
				      struct dsync_mailbox_node *node1,
				      struct dsync_mailbox_node *node2,
				      struct event *event)
{
	struct mailbox *box;
	struct mailbox_update update;
	struct dsync_mailbox_node *change_node;
	const char *change_vname;
	int ret = 0;

	i_zero(&update);
	guid_128_generate(update.mailbox_guid);

	/* just in case the duplication exists in both sides,
	   make them choose the same node */
	if (strcmp(dsync_mailbox_node_get_full_name(tree, node1),
		   dsync_mailbox_node_get_full_name(tree, node2)) <= 0)
		change_node = node1;
	else
		change_node = node2;

	change_vname = dsync_mailbox_node_get_full_name(tree, change_node);
	e_error(event, "Duplicate mailbox GUID %s for mailboxes %s and %s - "
		"giving a new GUID %s to %s",
		guid_128_to_string(node1->mailbox_guid),
		dsync_mailbox_node_get_full_name(tree, node1),
		dsync_mailbox_node_get_full_name(tree, node2),
		guid_128_to_string(update.mailbox_guid), change_vname);

	i_assert(node1->ns != NULL && node2->ns != NULL);
	box = mailbox_alloc(change_node->ns->list, change_vname, 0);
	if (mailbox_update(box, &update) < 0) {
		e_error(event, "Couldn't update mailbox %s GUID: %s",
			change_vname, mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	} else {
		memcpy(change_node->mailbox_guid, update.mailbox_guid,
		       sizeof(change_node->mailbox_guid));
	}
	mailbox_free(&box);
	return ret;
}

static bool
dsync_mailbox_info_is_wanted(const struct mailbox_info *info,
			     const char *box_name,
			     const char *const *exclude_mailboxes)
{
	const char *const *info_specialuses;
	unsigned int i;

	if (exclude_mailboxes == NULL &&
	    (box_name == NULL || box_name[0] != '\\'))
		return TRUE;

	info_specialuses = info->special_use == NULL ? NULL :
		t_strsplit(info->special_use, " ");
	/* include */
	if (box_name != NULL && box_name[0] == '\\') {
		if (info_specialuses == NULL ||
		    !str_array_icase_find(info_specialuses, box_name))
			return FALSE;
	}
	/* exclude */
	if (exclude_mailboxes == NULL)
		return TRUE;
	for (i = 0; exclude_mailboxes[i] != NULL; i++) {
		const char *exclude = exclude_mailboxes[i];

		if (exclude[0] == '\\') {
			/* special-use */
			if (info_specialuses != NULL &&
			    str_array_icase_find(info_specialuses, exclude))
				return FALSE;
		} else {
			/* mailbox with wildcards */
			if (wildcard_match(info->vname, exclude))
				return FALSE;
		}
	}
	return TRUE;
}

int dsync_mailbox_tree_fill(struct dsync_mailbox_tree *tree,
			    struct mail_namespace *ns, const char *box_name,
			    const guid_128_t box_guid,
			    const char *const *exclude_mailboxes,
			    char alt_char, struct event *event,
			    enum mail_error *error_r)
{
	const enum mailbox_list_iter_flags list_flags =
		/* FIXME: we'll skip symlinks, because we can't handle them
		   currently. in future we could detect them and create them
		   by creating the symlink. */
		MAILBOX_LIST_ITER_SKIP_ALIASES |
		MAILBOX_LIST_ITER_NO_AUTO_BOXES;
	const enum mailbox_list_iter_flags subs_list_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct mailbox_list_iterate_context *iter;
	struct dsync_mailbox_node *node, *dup_node1, *dup_node2;
	const struct mailbox_info *info;
	const char *list_pattern =
		box_name != NULL && box_name[0] != '\\' ? box_name : "*";
	int ret = 0;

	i_assert(mail_namespace_get_sep(ns) == tree->sep);

	/* assign namespace to its root, so it gets copied to children */
	if (ns->prefix_len > 0) {
		const char *vname = t_strndup(ns->prefix, ns->prefix_len-1);
		node = dsync_mailbox_tree_get(tree, vname);
		node->ns = ns;

		struct mailbox_info ns_info = {
			.vname = vname,
			.ns = ns,
		};
		if (dsync_mailbox_tree_add(
			tree, &ns_info, box_guid, alt_char, event, error_r) < 0)
			return -1;
	} else {
		tree->root.ns = ns;
	}

	/* first add all of the existing mailboxes */
	iter = mailbox_list_iter_init(ns->list, list_pattern, list_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (dsync_mailbox_info_is_wanted(info, box_name,
						 exclude_mailboxes)) {
			if (dsync_mailbox_tree_add(
				tree, info, box_guid, alt_char, event, error_r) < 0)
				ret = -1;
		}
	} T_END;
	if (mailbox_list_iter_deinit(&iter) < 0) {
		e_error(event, "Mailbox listing for namespace %s failed: %s",
			ns->set->name, mailbox_list_get_last_internal_error(ns->list, error_r));
		ret = -1;
	}

	/* add subscriptions */
	iter = mailbox_list_iter_init(ns->list, list_pattern, subs_list_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if (dsync_mailbox_tree_add_node(tree, info, alt_char, event, &node) == 0)
			node->subscribed = TRUE;
		else {
			*error_r = MAIL_ERROR_TEMP;
			ret = -1;
		}
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		e_error(event, "Mailbox listing for namespace %s failed: %s",
			ns->set->name, mailbox_list_get_last_internal_error(ns->list, error_r));
		ret = -1;
	}
	if (ret < 0)
		return -1;

	while (dsync_mailbox_tree_build_guid_hash(tree, &dup_node1,
						  &dup_node2) < 0) {
		if (dsync_mailbox_tree_fix_guid_duplicate(
			tree, dup_node1, dup_node2, event) < 0)
			return -1;
	}

	/* add timestamps */
	if (dsync_mailbox_tree_add_change_timestamps(tree, ns, event) < 0)
		return -1;
	return 0;
}
