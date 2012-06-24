/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "settings-parser.h"
#include "mail-namespace.h"
#include "doveadm-settings.h"
#include "dsync-slave.h"
#include "dsync-mailbox-tree.h"
#include "dsync-brain-private.h"

#include <ctype.h>

static bool dsync_brain_want_namespace(struct dsync_brain *brain,
				       struct mail_namespace *ns)
{
	if (brain->sync_ns == ns)
		return TRUE;

	return brain->sync_ns == NULL &&
		strcmp(ns->unexpanded_set->location,
		       SETTING_STRVAR_UNEXPANDED) == 0;
}

static void dsync_brain_check_namespaces(struct dsync_brain *brain)
{
	struct mail_namespace *ns, *first_ns = NULL;
	char sep;

	i_assert(brain->hierarchy_sep == '\0');

	if (brain->sync_ns != NULL) {
		brain->hierarchy_sep = mail_namespace_get_sep(brain->sync_ns);
		return;
	}

	for (ns = brain->user->namespaces; ns != NULL; ns = ns->next) {
		if (!dsync_brain_want_namespace(brain, ns))
			continue;

		sep = mail_namespace_get_sep(ns);
		if (brain->hierarchy_sep == '\0') {
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
		dsync_mailbox_tree_init(brain->hierarchy_sep);
	/* we'll convert remote mailbox names to use our own separator */
	brain->remote_mailbox_tree =
		dsync_mailbox_tree_init(brain->hierarchy_sep);

	/* fill the local mailbox tree */
	if (brain->sync_ns != NULL) {
		if (dsync_mailbox_tree_fill(brain->local_mailbox_tree,
					    brain->sync_ns) < 0)
			brain->failed = TRUE;
	} else {
		for (ns = brain->user->namespaces; ns != NULL; ns = ns->next) {
			if (!dsync_brain_want_namespace(brain, ns))
				continue;
			if (dsync_mailbox_tree_fill(brain->local_mailbox_tree,
						    ns) < 0)
				brain->failed = TRUE;
		}
	}

	brain->local_tree_iter =
		dsync_mailbox_tree_iter_init(brain->local_mailbox_tree);
}


void dsync_brain_send_mailbox_tree(struct dsync_brain *brain)
{
	struct dsync_mailbox_node *node;
	enum dsync_slave_send_ret ret;
	const char *full_name;
	char sep[2];

	sep[0] = brain->hierarchy_sep; sep[1] = '\0';
	while (dsync_mailbox_tree_iter_next(brain->local_tree_iter,
					    &full_name, &node)) {
		T_BEGIN {
			const char *const *parts;

			parts = t_strsplit(full_name, sep);
			ret = dsync_slave_send_mailbox_tree_node(brain->slave,
								 parts, node);
		} T_END;
		if (ret == DSYNC_SLAVE_SEND_RET_FULL)
			return;
	}
	dsync_mailbox_tree_iter_deinit(&brain->local_tree_iter);
	dsync_slave_send_end_of_list(brain->slave);

	brain->state = DSYNC_STATE_SEND_MAILBOX_TREE_DELETES;
}

void dsync_brain_send_mailbox_tree_deletes(struct dsync_brain *brain)
{
	const struct dsync_mailbox_delete *deletes;
	unsigned int count;

	deletes = dsync_mailbox_tree_get_deletes(brain->local_mailbox_tree,
						 &count);
	(void)dsync_slave_send_mailbox_deletes(brain->slave, deletes, count,
					       brain->hierarchy_sep);

	brain->state = DSYNC_STATE_RECV_MAILBOX_TREE;
}

static bool
dsync_namespace_match_parts(struct mail_namespace *ns,
			    const char *const *name_parts)
{
	const char *part, *prefix = ns->prefix;
	unsigned int part_len;
	char ns_sep = mail_namespace_get_sep(ns);

	for (; *name_parts != NULL && *prefix != '\0'; name_parts++) {
		part = *name_parts;
		part_len = strlen(part);

		if (strncmp(prefix, part, part_len) != 0)
			return FALSE;
		if (prefix[part_len] != ns_sep)
			return FALSE;
		prefix += part_len + 1;
	}
	return *name_parts != NULL;
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

static const char *
mailbox_name_cleanup(const char *input, char real_sep, char alt_char)
{
	char *output, *p;

	output = t_strdup_noconst(input);
	for (p = output; *p != '\0'; p++) {
		if (*p == real_sep || (uint8_t)*input < 32 ||
		    (uint8_t)*input >= 0x80)
			*p = alt_char;
	}
	return output;
}

static const char *mailbox_name_force_cleanup(const char *input, char alt_char)
{
	char *output, *p;

	output = t_strdup_noconst(input);
	for (p = output; *p != '\0'; p++) {
		if (!i_isalnum(*p))
			*p = alt_char;
	}
	return output;
}

static const char *
dsync_fix_mailbox_name(struct mail_namespace *ns, const char *vname,
		       char alt_char)
{
	const char *name;
	char list_sep;

	name = mailbox_list_get_storage_name(ns->list, vname);

	list_sep = mailbox_list_get_hierarchy_sep(ns->list);
	if (!mailbox_list_is_valid_create_name(ns->list, name)) {
		/* change any real separators to alt separators,
		   drop any potentially invalid characters */
		name = mailbox_name_cleanup(name, list_sep, alt_char);
	}
	if (!mailbox_list_is_valid_create_name(ns->list, name)) {
		/* still not working, apparently it's not valid mUTF-7.
		   just drop all non-alphanumeric characters. */
		name = mailbox_name_force_cleanup(name, alt_char);
	}
	if (!mailbox_list_is_valid_create_name(ns->list, name)) {
		/* probably some reserved name (e.g. dbox-Mails) */
		name = t_strconcat("_", name, NULL);
	}
	if (!mailbox_list_is_valid_create_name(ns->list, name)) {
		/* name is too long? just give up and generate a
		   unique name */
		guid_128_t guid;

		guid_128_generate(guid);
		name = guid_128_to_string(guid);
	}
	i_assert(mailbox_list_is_valid_create_name(ns->list, name));
	return mailbox_list_get_vname(ns->list, name);
}

static int
dsync_get_mailbox_name(struct dsync_brain *brain, const char *const *name_parts,
		       const char **name_r, struct mail_namespace **ns_r)
{
	struct mail_namespace *ns;
	const char *p;
	string_t *vname;
	char ns_sep, alt_char = doveadm_settings->dsync_alt_char[0];

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
				str_append_c(vname, alt_char);
		}
		str_append_c(vname, ns_sep);
	}
	str_truncate(vname, str_len(vname)-1);

	*name_r = dsync_fix_mailbox_name(ns, str_c(vname), alt_char);
	*ns_r = ns;
	return 0;
}

static void dsync_brain_mailbox_trees_sync(struct dsync_brain *brain)
{
	struct dsync_mailbox_tree_sync_ctx *ctx;
	const struct dsync_mailbox_tree_sync_change *change;

	ctx = dsync_mailbox_trees_sync_init(brain->local_mailbox_tree,
					    brain->remote_mailbox_tree);
	while ((change = dsync_mailbox_trees_sync_next(ctx)) != NULL) {
		if (dsync_brain_mailbox_tree_sync_change(brain, change) < 0)
			brain->failed = TRUE;
	}
	dsync_mailbox_trees_sync_deinit(&ctx);
}

bool dsync_brain_recv_mailbox_tree(struct dsync_brain *brain)
{
	const struct dsync_mailbox_node *remote_node;
	struct dsync_mailbox_node *node;
	const char *const *parts, *name;
	struct mail_namespace *ns;
	enum dsync_slave_recv_ret ret;
	char sep[2];
	bool changed = FALSE;

	while ((ret = dsync_slave_recv_mailbox_tree_node(brain->slave, &parts,
							 &remote_node)) > 0) {
		if (dsync_get_mailbox_name(brain, parts, &name, &ns) < 0) {
			sep[0] = brain->hierarchy_sep; sep[1] = '\0';
			i_error("Couldn't find namespace for mailbox %s",
				t_strarray_join(parts, sep));
			brain->failed = TRUE;
			return TRUE;
		}
		node = dsync_mailbox_tree_get(brain->remote_mailbox_tree, name);
		node->ns = ns;
		dsync_mailbox_node_copy_data(node, remote_node);
	}
	if (ret == DSYNC_SLAVE_RECV_RET_FINISHED) {
		if (dsync_mailbox_tree_build_guid_hash(brain->remote_mailbox_tree) < 0)
			brain->failed = TRUE;

		brain->state = DSYNC_STATE_RECV_MAILBOX_TREE_DELETES;
		changed = TRUE;
	}
	return changed;
}

static void
dsync_brain_mailbox_tree_add_delete(struct dsync_mailbox_tree *tree,
				    struct dsync_mailbox_tree *other_tree,
				    const struct dsync_mailbox_delete *other_del)
{
	const struct dsync_mailbox_node *node;
	struct dsync_mailbox_node *other_node;
	const char *name;

	/* see if we can find the deletion based on mailbox tree that should
	   still have the mailbox */
	node = dsync_mailbox_tree_find_delete(tree, other_del);
	if (node == NULL)
		return;

	/* make a node for it in the other mailbox tree */
	name = dsync_mailbox_node_get_full_name(tree, node);
	other_node = dsync_mailbox_tree_get(other_tree, name);

	if (!guid_128_is_empty(other_node->mailbox_guid) ||
	    (other_node->existence == DSYNC_MAILBOX_NODE_EXISTS &&
	     !other_del->delete_mailbox)) {
		/* other side has already created a new mailbox or
		   directory with this name, we can't delete it */
		return;
	}

	/* ok, mark the other node deleted */
	if (other_del->delete_mailbox) {
		memcpy(other_node->mailbox_guid, node->mailbox_guid,
		       sizeof(other_node->mailbox_guid));
	}
	i_assert(other_node->ns == NULL || other_node->ns == node->ns);
	other_node->ns = node->ns;
	other_node->existence = DSYNC_MAILBOX_NODE_DELETED;

	if (dsync_mailbox_tree_guid_hash_add(other_tree, other_node) < 0)
		i_unreached();
}

bool dsync_brain_recv_mailbox_tree_deletes(struct dsync_brain *brain)
{
	const struct dsync_mailbox_delete *deletes;
	unsigned int i, count;
	char sep;

	if (dsync_slave_recv_mailbox_deletes(brain->slave, &deletes, &count,
					     &sep) == 0)
		return FALSE;

	/* apply remote's mailbox deletions based on our local tree */
	dsync_mailbox_tree_set_remote_sep(brain->local_mailbox_tree, sep);
	for (i = 0; i < count; i++) {
		dsync_brain_mailbox_tree_add_delete(brain->local_mailbox_tree,
						    brain->remote_mailbox_tree,
						    &deletes[i]);
	}

	/* apply local mailbox deletions based on remote tree */
	deletes = dsync_mailbox_tree_get_deletes(brain->local_mailbox_tree,
						 &count);
	dsync_mailbox_tree_set_remote_sep(brain->remote_mailbox_tree,
					  brain->hierarchy_sep);
	for (i = 0; i < count; i++) {
		dsync_brain_mailbox_tree_add_delete(brain->remote_mailbox_tree,
						    brain->local_mailbox_tree,
						    &deletes[i]);
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
