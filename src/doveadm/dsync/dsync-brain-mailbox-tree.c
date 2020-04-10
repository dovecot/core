/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "dsync-ibc.h"
#include "dsync-mailbox-tree.h"
#include "dsync-brain-private.h"

#include <ctype.h>

static void dsync_brain_check_namespaces(struct dsync_brain *brain)
{
	struct mail_namespace *ns, *first_ns = NULL;
	char sep, escape_char;

	i_assert(brain->hierarchy_sep == '\0');
	i_assert(brain->escape_char == '\0');

	for (ns = brain->user->namespaces; ns != NULL; ns = ns->next) {
		if (!dsync_brain_want_namespace(brain, ns))
			continue;

		sep = mail_namespace_get_sep(ns);
		escape_char = mailbox_list_get_settings(ns->list)->vname_escape_char;
		if (first_ns == NULL) {
			brain->hierarchy_sep = sep;
			brain->escape_char = escape_char;
			first_ns = ns;
		} else if (brain->hierarchy_sep != sep) {
			i_fatal("Synced namespaces have conflicting separators "
				"('%c' for prefix=\"%s\", '%c' for prefix=\"%s\")",
				brain->hierarchy_sep, first_ns->prefix,
				sep, ns->prefix);
		} else if (brain->escape_char != escape_char) {
			i_fatal("Synced namespaces have conflicting escape chars "
				"('%c' for prefix=\"%s\", '%c' for prefix=\"%s\")",
				brain->escape_char, first_ns->prefix,
				escape_char, ns->prefix);
		}
	}
	if (brain->hierarchy_sep != '\0')
		return;

	i_fatal("All your namespaces have a location setting. "
		"Only namespaces with empty location settings are converted. "
		"(One namespace should default to mail_location setting)");
}

void dsync_brain_mailbox_trees_init(struct dsync_brain *brain)
{
	struct mail_namespace *ns;

	dsync_brain_check_namespaces(brain);

	brain->local_mailbox_tree =
		dsync_mailbox_tree_init(brain->hierarchy_sep,
					brain->escape_char, brain->alt_char);
	/* we'll convert remote mailbox names to use our own separator */
	brain->remote_mailbox_tree =
		dsync_mailbox_tree_init(brain->hierarchy_sep,
					brain->escape_char, brain->alt_char);

	/* fill the local mailbox tree */
	for (ns = brain->user->namespaces; ns != NULL; ns = ns->next) {
		if (!dsync_brain_want_namespace(brain, ns))
			continue;
		if (brain->debug)
			i_debug("brain %c: Namespace %s has location %s",
				brain->master_brain ? 'M' : 'S',
				ns->prefix, ns->set->location);
		if (dsync_mailbox_tree_fill(brain->local_mailbox_tree, ns,
					    brain->sync_box,
					    brain->sync_box_guid,
					    brain->exclude_mailboxes,
					    &brain->mail_error) < 0) {
			brain->failed = TRUE;
			break;
		}
	}

	brain->local_tree_iter =
		dsync_mailbox_tree_iter_init(brain->local_mailbox_tree);
}

static const char *const *
dsync_brain_mailbox_to_parts(struct dsync_brain *brain, const char *name)
{
	char sep[] = { brain->hierarchy_sep, '\0' };
	char **parts = p_strsplit(unsafe_data_stack_pool, name, sep);
	for (unsigned int i = 0; parts[i] != NULL; i++) {
		mailbox_list_name_unescape((const char **)&parts[i],
					   brain->escape_char);
	}
	return (const char *const *)parts;
}

void dsync_brain_send_mailbox_tree(struct dsync_brain *brain)
{
	struct dsync_mailbox_node *node;
	enum dsync_ibc_send_ret ret;
	const char *full_name;

	while (dsync_mailbox_tree_iter_next(brain->local_tree_iter,
					    &full_name, &node)) {
		if (node->ns == NULL) {
			/* This node was created when adding a namespace prefix
			   to the tree that has multiple hierarchical names,
			   but the parent names don't belong to any synced
			   namespace. For example when syncing "-n Shared/user/"
			   so "Shared/" is skipped. Or if there is e.g.
			   "Public/files/" namespace prefix, but no "Public/"
			   namespace at all. */
			continue;
		}

		T_BEGIN {
			const char *const *parts;

			if (brain->debug) {
				i_debug("brain %c: Local mailbox tree: %s %s",
					brain->master_brain ? 'M' : 'S', full_name,
					dsync_mailbox_node_to_string(node));
			}

			parts = dsync_brain_mailbox_to_parts(brain, full_name);
			ret = dsync_ibc_send_mailbox_tree_node(brain->ibc,
							       parts, node);
		} T_END;
		if (ret == DSYNC_IBC_SEND_RET_FULL)
			return;
	}
	dsync_mailbox_tree_iter_deinit(&brain->local_tree_iter);
	dsync_ibc_send_end_of_list(brain->ibc, DSYNC_IBC_EOL_MAILBOX_TREE);

	brain->state = DSYNC_STATE_SEND_MAILBOX_TREE_DELETES;
}

void dsync_brain_send_mailbox_tree_deletes(struct dsync_brain *brain)
{
	const struct dsync_mailbox_delete *deletes;
	unsigned int count;

	deletes = dsync_mailbox_tree_get_deletes(brain->local_mailbox_tree,
						 &count);
	dsync_ibc_send_mailbox_deletes(brain->ibc, deletes, count,
				       brain->hierarchy_sep,
				       brain->escape_char);

	brain->state = DSYNC_STATE_RECV_MAILBOX_TREE;
}

static bool
dsync_namespace_match_parts(struct mail_namespace *ns,
			    const char *const *name_parts)
{
	const char *part, *suffix, *prefix = ns->prefix;
	char ns_sep = mail_namespace_get_sep(ns);

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
	    strcmp(name_parts[0], "INBOX") == 0 && name_parts[1] == NULL)
		return TRUE;

	for (; *name_parts != NULL && *prefix != '\0'; name_parts++) {
		part = *name_parts;

		if (!str_begins(prefix, part, &suffix))
			return FALSE;
		if (suffix[0] != ns_sep)
			return FALSE;
		prefix = suffix + 1;
	}
	if (*name_parts != NULL) {
		/* namespace prefix found with a mailbox */
		return TRUE;
	}
	if (*prefix == '\0') {
		/* namespace prefix itself matched */
		return TRUE;
	}
	return FALSE;
}

static struct mail_namespace *
dsync_find_namespace(struct dsync_brain *brain, const char *const *name_parts)
{
	struct mail_namespace *ns, *best_ns = NULL;

	for (ns = brain->user->namespaces; ns != NULL; ns = ns->next) {
		if (!dsync_brain_want_namespace(brain, ns))
			continue;

		if (ns->prefix_len == 0) {
			/* prefix="" is the fallback namespace */
			if (best_ns == NULL)
				best_ns = ns;
		} else if (dsync_namespace_match_parts(ns, name_parts)) {
			if (best_ns == NULL ||
			    best_ns->prefix_len < ns->prefix_len)
				best_ns = ns;
		}
	}
	return best_ns;
}

static bool
dsync_is_valid_name(struct mail_namespace *ns, const char *vname)
{
	struct mailbox *box;
	bool ret;

	box = mailbox_alloc(ns->list, vname, MAILBOX_FLAG_READONLY);
	ret = mailbox_verify_create_name(box) == 0;
	mailbox_free(&box);
	return ret;
}

static bool
dsync_is_valid_name_until(struct mail_namespace *ns, string_t *vname_full,
			  unsigned int end_pos)
{
	const char *vname;
	if (end_pos == str_len(vname_full))
		vname = str_c(vname_full);
	else
		vname = t_strndup(str_c(vname_full), end_pos);
	return dsync_is_valid_name(ns, vname);
}

static bool
dsync_fix_mailbox_name_until(struct mail_namespace *ns, string_t *vname_full,
			     char alt_char, unsigned int start_pos,
			     unsigned int *_end_pos)
{
	unsigned int end_pos = *_end_pos;
	unsigned int i;

	if (dsync_is_valid_name_until(ns, vname_full, end_pos))
		return TRUE;

	/* 1) change any real separators to alt separators (this
	   wouldn't be necessary with listescape, but don't bother
	   detecting it) */
	char list_sep = mailbox_list_get_hierarchy_sep(ns->list);
	char ns_sep = mail_namespace_get_sep(ns);
	if (list_sep != ns_sep) {
		char *v = str_c_modifiable(vname_full);
		for (i = start_pos; i < end_pos; i++) {
			if (v[i] == list_sep)
				v[i] = alt_char;
		}
		if (dsync_is_valid_name_until(ns, vname_full, end_pos))
			return TRUE;
	}

	/* 2) '/' characters aren't valid without listescape */
	if (ns_sep != '/' && list_sep != '/') {
		char *v = str_c_modifiable(vname_full);
		for (i = start_pos; i < end_pos; i++) {
			if (v[i] == '/')
				v[i] = alt_char;
		}
		if (dsync_is_valid_name_until(ns, vname_full, end_pos))
			return TRUE;
	}

	/* 3) probably some reserved name (e.g. dbox-Mails or ..) */
	str_insert(vname_full, start_pos, "_"); end_pos++; *_end_pos += 1;
	if (dsync_is_valid_name_until(ns, vname_full, end_pos))
		return TRUE;

	return FALSE;
}

static void
dsync_fix_mailbox_name(struct mail_namespace *ns, string_t *vname_str,
		       char alt_char)
{
	const char *old_vname;
	char *vname;
	char ns_sep = mail_namespace_get_sep(ns);
	guid_128_t guid;
	unsigned int i, start_pos;

	vname = str_c_modifiable(vname_str);
	if (strncmp(vname, ns->prefix, ns->prefix_len) == 0)
		start_pos = ns->prefix_len;
	else
		start_pos = 0;

	/* replace control chars */
	for (i = start_pos; vname[i] != '\0'; i++) {
		if ((unsigned char)vname[i] < ' ')
			vname[i] = alt_char;
	}
	/* make it valid UTF8 */
	if (!uni_utf8_str_is_valid(vname)) {
		old_vname = t_strdup(vname + start_pos);
		str_truncate(vname_str, start_pos);
		if (uni_utf8_get_valid_data((const void *)old_vname,
					    strlen(old_vname), vname_str))
			i_unreached();
		vname = str_c_modifiable(vname_str);
	}
	if (dsync_is_valid_name(ns, vname))
		return;

	/* Check/fix each hierarchical name separately */
	const char *p;
	do {
		i_assert(start_pos <= str_len(vname_str));
		p = strchr(str_c(vname_str) + start_pos, ns_sep);
		unsigned int end_pos;
		if (p == NULL)
			end_pos = str_len(vname_str);
		else
			end_pos = p - str_c(vname_str);

		if (!dsync_fix_mailbox_name_until(ns, vname_str, alt_char,
						  start_pos, &end_pos)) {
			/* Couldn't fix it. Name is too long? Just give up and
			   generate a unique name. */
			guid_128_generate(guid);
			str_truncate(vname_str, 0);
			str_append(vname_str, ns->prefix);
			str_append(vname_str, guid_128_to_string(guid));
			i_assert(dsync_is_valid_name(ns, str_c(vname_str)));
			break;
		}
		start_pos = end_pos + 1;
	} while (p != NULL);
}

static int
dsync_get_mailbox_name(struct dsync_brain *brain, const char *const *name_parts,
		       const char **name_r, struct mail_namespace **ns_r)
{
	struct mail_namespace *ns;
	const char *p;
	string_t *vname;
	char ns_sep;

	i_assert(*name_parts != NULL);

	ns = dsync_find_namespace(brain, name_parts);
	if (ns == NULL)
		return -1;
	ns_sep = mail_namespace_get_sep(ns);

	/* build the mailbox name */
	char escape_chars[] = {
		brain->escape_char,
		ns_sep,
		'\0'
	};
	struct dsync_mailbox_list *dlist = DSYNC_LIST_CONTEXT(ns->list);
	if (dlist != NULL && !dlist->have_orig_escape_char) {
		/* The escape character was added only for dsync internally.
		   Normally there is no escape character configured. Change
		   the mailbox names so that it doesn't rely on it. */
		escape_chars[0] = '\0';
	}
	vname = t_str_new(128);
	for (; *name_parts != NULL; name_parts++) {
		if (escape_chars[0] != '\0') {
			mailbox_list_name_escape(*name_parts, escape_chars,
						 vname);
		} else {
			for (p = *name_parts; *p != '\0'; p++) {
				if (*p != ns_sep)
					str_append_c(vname, *p);
				else
					str_append_c(vname, brain->alt_char);
			}
		}
		str_append_c(vname, ns_sep);
	}
	str_truncate(vname, str_len(vname)-1);

	dsync_fix_mailbox_name(ns, vname, brain->alt_char);
	*name_r = str_c(vname);
	*ns_r = ns;
	return 0;
}

static void dsync_brain_mailbox_trees_sync(struct dsync_brain *brain)
{
	struct dsync_mailbox_tree_sync_ctx *ctx;
	const struct dsync_mailbox_tree_sync_change *change;
	enum dsync_mailbox_trees_sync_type sync_type;
	enum dsync_mailbox_trees_sync_flags sync_flags =
		(brain->debug ? DSYNC_MAILBOX_TREES_SYNC_FLAG_DEBUG : 0) |
		(brain->master_brain ? DSYNC_MAILBOX_TREES_SYNC_FLAG_MASTER_BRAIN : 0);
	int ret;

	if (brain->no_backup_overwrite)
		sync_type = DSYNC_MAILBOX_TREES_SYNC_TYPE_TWOWAY;
	else if (brain->backup_send)
		sync_type = DSYNC_MAILBOX_TREES_SYNC_TYPE_PRESERVE_LOCAL;
	else if (brain->backup_recv)
		sync_type = DSYNC_MAILBOX_TREES_SYNC_TYPE_PRESERVE_REMOTE;
	else
		sync_type = DSYNC_MAILBOX_TREES_SYNC_TYPE_TWOWAY;

	ctx = dsync_mailbox_trees_sync_init(brain->local_mailbox_tree,
					    brain->remote_mailbox_tree,
					    sync_type, sync_flags);
	while ((change = dsync_mailbox_trees_sync_next(ctx)) != NULL) {
		T_BEGIN {
			ret = dsync_brain_mailbox_tree_sync_change(
				brain, change, &brain->mail_error);
		} T_END;
		if (ret < 0) {
			brain->failed = TRUE;
			break;
		}
	}
	if (dsync_mailbox_trees_sync_deinit(&ctx) < 0)
		brain->failed = TRUE;
}

static int
dsync_brain_recv_mailbox_tree_add(struct dsync_brain *brain,
				  const char *const *parts,
				  const struct dsync_mailbox_node *remote_node,
				  const char *sep)
{
	struct dsync_mailbox_node *node;
	struct mail_namespace *ns;
	const char *name;

	if (dsync_get_mailbox_name(brain, parts, &name, &ns) < 0)
		return -1;
	if (brain->debug) {
		i_debug("brain %c: Remote mailbox tree: %s %s",
			brain->master_brain ? 'M' : 'S',
			t_strarray_join(parts, sep),
			dsync_mailbox_node_to_string(remote_node));
	}
	node = dsync_mailbox_tree_get(brain->remote_mailbox_tree, name);
	node->ns = ns;
	dsync_mailbox_node_copy_data(node, remote_node);
	return 0;
}

bool dsync_brain_recv_mailbox_tree(struct dsync_brain *brain)
{
	const struct dsync_mailbox_node *remote_node;
	struct dsync_mailbox_node *dup_node1, *dup_node2;
	const char *const *parts;
	enum dsync_ibc_recv_ret ret;
	int ret2;
	char sep[2];
	bool changed = FALSE;

	sep[0] = brain->hierarchy_sep; sep[1] = '\0';
	while ((ret = dsync_ibc_recv_mailbox_tree_node(brain->ibc, &parts,
						       &remote_node)) > 0) {
		T_BEGIN {
			ret2 = dsync_brain_recv_mailbox_tree_add(
					brain, parts, remote_node, sep);
		} T_END;
		if (ret2 < 0) {
			i_error("Couldn't find namespace for mailbox %s",
				t_strarray_join(parts, sep));
			brain->failed = TRUE;
			return TRUE;
		}
	}
	if (ret != DSYNC_IBC_RECV_RET_FINISHED)
		return changed;

	if (dsync_mailbox_tree_build_guid_hash(brain->remote_mailbox_tree,
					       &dup_node1, &dup_node2) < 0) {
		i_error("Remote sent duplicate mailbox GUID %s for mailboxes %s and %s",
			guid_128_to_string(dup_node1->mailbox_guid),
			dsync_mailbox_node_get_full_name(brain->remote_mailbox_tree,
							 dup_node1),
			dsync_mailbox_node_get_full_name(brain->remote_mailbox_tree,
							 dup_node2));
		brain->failed = TRUE;
	}

	brain->state = DSYNC_STATE_RECV_MAILBOX_TREE_DELETES;
	return TRUE;
}

static void
dsync_brain_mailbox_tree_add_delete(struct dsync_mailbox_tree *tree,
				    struct dsync_mailbox_tree *other_tree,
				    const struct dsync_mailbox_delete *other_del,
				    const struct dsync_mailbox_node **node_r,
				    const char **status_r)
{
	const struct dsync_mailbox_node *node;
	struct dsync_mailbox_node *other_node, *old_node;
	const char *name;

	/* see if we can find the deletion based on mailbox tree that should
	   still have the mailbox */
	node = *node_r = dsync_mailbox_tree_find_delete(tree, other_del);
	if (node == NULL) {
		*status_r = "not found";
		return;
	}

	switch (other_del->type) {
	case DSYNC_MAILBOX_DELETE_TYPE_MAILBOX:
		/* mailbox is always deleted */
		break;
	case DSYNC_MAILBOX_DELETE_TYPE_DIR:
		if (other_del->timestamp <= node->last_renamed_or_created) {
			/* we don't want to delete this directory, we already
			   have a newer timestamp for it */
			*status_r = "keep directory, we have a newer timestamp";
			return;
		}
		break;
	case DSYNC_MAILBOX_DELETE_TYPE_UNSUBSCRIBE:
		if (other_del->timestamp <= node->last_subscription_change) {
			/* we don't want to unsubscribe, since we already have
			   a newer subscription timestamp */
			*status_r = "keep subscription, we have a newer timestamp";
			return;
		}
		break;
	}

	/* make a node for it in the other mailbox tree */
	name = dsync_mailbox_node_get_full_name(tree, node);
	other_node = dsync_mailbox_tree_get(other_tree, name);

	if (other_node->existence == DSYNC_MAILBOX_NODE_EXISTS &&
	    (!guid_128_is_empty(other_node->mailbox_guid) ||
	     other_del->type != DSYNC_MAILBOX_DELETE_TYPE_MAILBOX)) {
		/* other side has already created a new mailbox or
		   directory with this name, we can't delete it */
		*status_r = "name has already been recreated";
		return;
	}

	/* ok, mark the other node deleted */
	if (other_del->type == DSYNC_MAILBOX_DELETE_TYPE_MAILBOX) {
		memcpy(other_node->mailbox_guid, node->mailbox_guid,
		       sizeof(other_node->mailbox_guid));
	}
	if (other_node->ns != node->ns && other_node->ns != NULL) {
		/* namespace mismatch for this node. this shouldn't happen
		   normally, but especially during some misconfigurations it's
		   possible that one side has created mailboxes that conflict
		   with another namespace's prefix. since we're here because
		   one of the mailboxes was deleted, we'll just ignore this. */
		*status_r = "namespace mismatch";
		return;
	}
	other_node->ns = node->ns;
	if (other_del->type != DSYNC_MAILBOX_DELETE_TYPE_UNSUBSCRIBE) {
		other_node->existence = DSYNC_MAILBOX_NODE_DELETED;
		*status_r = "marked as deleted";
	} else {
		other_node->last_subscription_change = other_del->timestamp;
		other_node->subscribed = FALSE;
		*status_r = "marked as unsubscribed";
	}

	if (dsync_mailbox_tree_guid_hash_add(other_tree, other_node,
					     &old_node) < 0)
		i_unreached();
}

bool dsync_brain_recv_mailbox_tree_deletes(struct dsync_brain *brain)
{
	const struct dsync_mailbox_node *node;
	const char *status;
	const struct dsync_mailbox_delete *deletes;
	unsigned int i, count;
	char sep, escape_char;

	if (dsync_ibc_recv_mailbox_deletes(brain->ibc, &deletes, &count,
					   &sep, &escape_char) == 0)
		return FALSE;

	/* apply remote's mailbox deletions based on our local tree */
	dsync_mailbox_tree_set_remote_chars(brain->local_mailbox_tree, sep,
					    escape_char);
	for (i = 0; i < count; i++) {
		dsync_brain_mailbox_tree_add_delete(brain->local_mailbox_tree,
						    brain->remote_mailbox_tree,
						    &deletes[i], &node, &status);
		if (brain->debug) {
			const char *node_name = node == NULL ? "" :
				dsync_mailbox_node_get_full_name(brain->local_mailbox_tree, node);
			i_debug("brain %c: Remote mailbox tree deletion: guid=%s type=%s timestamp=%ld name=%s local update=%s",
				brain->master_brain ? 'M' : 'S',
				guid_128_to_string(deletes[i].guid),
				dsync_mailbox_delete_type_to_string(deletes[i].type),
				deletes[i].timestamp, node_name, status);
		}
	}

	/* apply local mailbox deletions based on remote tree */
	deletes = dsync_mailbox_tree_get_deletes(brain->local_mailbox_tree,
						 &count);
	dsync_mailbox_tree_set_remote_chars(brain->remote_mailbox_tree,
					    brain->hierarchy_sep,
					    brain->escape_char);
	for (i = 0; i < count; i++) {
		dsync_brain_mailbox_tree_add_delete(brain->remote_mailbox_tree,
						    brain->local_mailbox_tree,
						    &deletes[i], &node, &status);
	}

	dsync_brain_mailbox_trees_sync(brain);
	brain->state = brain->master_brain ?
		DSYNC_STATE_MASTER_SEND_MAILBOX :
		DSYNC_STATE_SLAVE_RECV_MAILBOX;
	i_assert(brain->local_tree_iter == NULL);
	brain->local_tree_iter =
		dsync_mailbox_tree_iter_init(brain->local_mailbox_tree);
	return TRUE;
}
