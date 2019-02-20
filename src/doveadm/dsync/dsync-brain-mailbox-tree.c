/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-namespace.h"
#include "dsync-ibc.h"
#include "dsync-mailbox-tree.h"
#include "dsync-brain-private.h"

#include <ctype.h>

static void dsync_brain_check_namespaces(struct dsync_brain *brain)
{
	struct mail_namespace *ns, *first_ns = NULL;
	char sep;

	i_assert(brain->hierarchy_sep == '\0');

	for (ns = brain->user->namespaces; ns != NULL; ns = ns->next) {
		if (!dsync_brain_want_namespace(brain, ns))
			continue;

		sep = mail_namespace_get_sep(ns);
		if (first_ns == NULL) {
			brain->hierarchy_sep = sep;
			first_ns = ns;
		} else if (brain->hierarchy_sep != sep) {
			i_fatal("Synced namespaces have conflicting separators "
				"('%c' for prefix=\"%s\", '%c' for prefix=\"%s\")",
				brain->hierarchy_sep, first_ns->prefix,
				sep, ns->prefix);
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
		dsync_mailbox_tree_init(brain->hierarchy_sep, brain->alt_char);
	/* we'll convert remote mailbox names to use our own separator */
	brain->remote_mailbox_tree =
		dsync_mailbox_tree_init(brain->hierarchy_sep, brain->alt_char);

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


void dsync_brain_send_mailbox_tree(struct dsync_brain *brain)
{
	struct dsync_mailbox_node *node;
	enum dsync_ibc_send_ret ret;
	const char *full_name;
	char sep[2];

	sep[0] = brain->hierarchy_sep; sep[1] = '\0';
	while (dsync_mailbox_tree_iter_next(brain->local_tree_iter,
					    &full_name, &node)) {
		T_BEGIN {
			const char *const *parts;

			if (brain->debug) {
				i_debug("brain %c: Local mailbox tree: %s %s",
					brain->master_brain ? 'M' : 'S', full_name,
					dsync_mailbox_node_to_string(node));
			}

			parts = t_strsplit(full_name, sep);
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
				       brain->hierarchy_sep);

	brain->state = DSYNC_STATE_RECV_MAILBOX_TREE;
}

static bool
dsync_namespace_match_parts(struct mail_namespace *ns,
			    const char *const *name_parts)
{
	const char *part, *prefix = ns->prefix;
	size_t part_len;
	char ns_sep = mail_namespace_get_sep(ns);

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
	    strcmp(name_parts[0], "INBOX") == 0 && name_parts[1] == NULL)
		return TRUE;

	for (; *name_parts != NULL && *prefix != '\0'; name_parts++) {
		part = *name_parts;
		part_len = strlen(part);

		if (!str_begins(prefix, part))
			return FALSE;
		if (prefix[part_len] != ns_sep)
			return FALSE;
		prefix += part_len + 1;
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

static void
dsync_fix_mailbox_name(struct mail_namespace *ns, string_t *vname_str,
		       char alt_char)
{
	const char *old_vname;
	char *vname, list_sep = mailbox_list_get_hierarchy_sep(ns->list);
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

	/* 1) change any real separators to alt separators (this wouldn't
	   be necessary with listescape, but don't bother detecting it) */
	if (list_sep != mail_namespace_get_sep(ns)) {
		for (i = start_pos; vname[i] != '\0'; i++) {
			if (vname[i] == list_sep)
				vname[i] = alt_char;
		}
		if (dsync_is_valid_name(ns, vname))
			return;
	}
	/* 2) '/' characters aren't valid without listescape */
	if (mail_namespace_get_sep(ns) != '/' && list_sep != '/') {
		for (i = start_pos; vname[i] != '\0'; i++) {
			if (vname[i] == '/')
				vname[i] = alt_char;
		}
		if (dsync_is_valid_name(ns, vname))
			return;
	}
	/* 3) probably some reserved name (e.g. dbox-Mails) */
	str_insert(vname_str, ns->prefix_len, "_");
	if (dsync_is_valid_name(ns, str_c(vname_str)))
		return;

	/* 4) name is too long? just give up and generate a unique name */
	guid_128_generate(guid);
	str_truncate(vname_str, 0);
	str_append(vname_str, ns->prefix);
	str_append(vname_str, guid_128_to_string(guid));
	i_assert(dsync_is_valid_name(ns, str_c(vname_str)));
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
	vname = t_str_new(128);
	for (; *name_parts != NULL; name_parts++) {
		for (p = *name_parts; *p != '\0'; p++) {
			if (*p != ns_sep)
				str_append_c(vname, *p);
			else
				str_append_c(vname, brain->alt_char);
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
		(brain->master_brain ? DSYNC_MAILBOX_TREES_SYNC_FLAG_MASTER_BRAIN : 0) |
		(brain->no_mailbox_renames ? DSYNC_MAILBOX_TREES_SYNC_FLAG_NO_RENAMES : 0);

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
		if (dsync_brain_mailbox_tree_sync_change(brain, change,
							 &brain->mail_error) < 0) {
			brain->failed = TRUE;
			break;
		}
	}
	if (dsync_mailbox_trees_sync_deinit(&ctx) < 0)
		brain->failed = TRUE;
}

bool dsync_brain_recv_mailbox_tree(struct dsync_brain *brain)
{
	const struct dsync_mailbox_node *remote_node;
	struct dsync_mailbox_node *node, *dup_node1, *dup_node2;
	const char *const *parts, *name;
	struct mail_namespace *ns;
	enum dsync_ibc_recv_ret ret;
	char sep[2];
	bool changed = FALSE;

	sep[0] = brain->hierarchy_sep; sep[1] = '\0';
	while ((ret = dsync_ibc_recv_mailbox_tree_node(brain->ibc, &parts,
						       &remote_node)) > 0) {
		if (dsync_get_mailbox_name(brain, parts, &name, &ns) < 0) {
			i_error("Couldn't find namespace for mailbox %s",
				t_strarray_join(parts, sep));
			brain->failed = TRUE;
			return TRUE;
		}
		if (brain->debug) {
			i_debug("brain %c: Remote mailbox tree: %s %s",
				brain->master_brain ? 'M' : 'S',
				t_strarray_join(parts, sep),
				dsync_mailbox_node_to_string(remote_node));
		}
		node = dsync_mailbox_tree_get(brain->remote_mailbox_tree, name);
		node->ns = ns;
		dsync_mailbox_node_copy_data(node, remote_node);
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
	char sep;

	if (dsync_ibc_recv_mailbox_deletes(brain->ibc, &deletes, &count,
					   &sep) == 0)
		return FALSE;

	/* apply remote's mailbox deletions based on our local tree */
	dsync_mailbox_tree_set_remote_sep(brain->local_mailbox_tree, sep);
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
	dsync_mailbox_tree_set_remote_sep(brain->remote_mailbox_tree,
					  brain->hierarchy_sep);
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
