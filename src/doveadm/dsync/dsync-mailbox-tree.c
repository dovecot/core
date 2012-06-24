/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "doveadm-settings.h"
#include "mailbox-list-private.h"
#include "dsync-mailbox-tree-private.h"

struct dsync_mailbox_tree_iter {
	struct dsync_mailbox_tree *tree;

	struct dsync_mailbox_node *cur;
	string_t *name;
};

struct dsync_mailbox_tree *dsync_mailbox_tree_init(char sep)
{
	struct dsync_mailbox_tree *tree;
	pool_t pool;

	i_assert(sep != '\0');

	pool = pool_alloconly_create("dsync mailbox tree", 4096);
	tree = p_new(pool, struct dsync_mailbox_tree, 1);
	tree->pool = pool;
	tree->sep = tree->sep_str[0] = sep;
	tree->root.name = "";
	i_array_init(&tree->deletes, 32);
	return tree;
}

void dsync_mailbox_tree_deinit(struct dsync_mailbox_tree **_tree)
{
	struct dsync_mailbox_tree *tree = *_tree;

	*_tree = NULL;
	if (tree->name128_hash != NULL)
		hash_table_destroy(&tree->name128_hash);
	if (tree->guid_hash != NULL)
		hash_table_destroy(&tree->guid_hash);
	array_free(&tree->deletes);
	pool_unref(&tree->pool);
}

static struct dsync_mailbox_node *
dsync_mailbox_node_find(struct dsync_mailbox_node *nodes, const char *name)
{
	for (; nodes != NULL; nodes = nodes->next) {
		if (strcmp(name, nodes->name) == 0)
			return nodes;
	}
	return NULL;
}

struct dsync_mailbox_node *
dsync_mailbox_tree_lookup(struct dsync_mailbox_tree *tree,
			  const char *full_name)
{
	struct dsync_mailbox_node *node = &tree->root;

	T_BEGIN {
		const char *const *path;

		path = t_strsplit(full_name, tree->sep_str);
		for (; *path != '\0' && node != NULL; path++)
			node = dsync_mailbox_node_find(node->first_child, *path);
	} T_END;
	return node;
}

struct dsync_mailbox_node *
dsync_mailbox_tree_get(struct dsync_mailbox_tree *tree, const char *full_name)
{
	struct dsync_mailbox_node *parent = NULL, *node = &tree->root;

	i_assert(tree->iter_count == 0);

	T_BEGIN {
		const char *const *path;

		/* find the existing part */
		path = t_strsplit(full_name, tree->sep_str);
		for (; *path != '\0'; path++) {
			parent = node;
			node = dsync_mailbox_node_find(node->first_child, *path);
			if (node == NULL)
				break;
		}
		/* create the rest */
		for (; *path != '\0'; path++) {
			node = p_new(tree->pool, struct dsync_mailbox_node, 1);
			node->name = p_strdup(tree->pool, *path);
			node->ns = parent->ns;
			node->parent = parent;
			node->next = parent->first_child;
			parent->first_child = node;
			parent = node;
		}
	} T_END;
	return node;
}

static void
node_get_full_name_recurse(const struct dsync_mailbox_tree *tree,
			   const struct dsync_mailbox_node *node, string_t *str)
{
	if (node->parent != &tree->root)
		node_get_full_name_recurse(tree, node->parent, str);

	str_append(str, node->name);
	str_append_c(str, tree->sep);
}

const char *dsync_mailbox_node_get_full_name(const struct dsync_mailbox_tree *tree,
					     const struct dsync_mailbox_node *node)
{
	string_t *str = t_str_new(128);

	i_assert(node->parent != NULL);

	node_get_full_name_recurse(tree, node, str);
	/* remove the trailing separator */
	str_truncate(str, str_len(str)-1);
	return str_c(str);
}

void dsync_mailbox_node_copy_data(struct dsync_mailbox_node *dest,
				  const struct dsync_mailbox_node *src)
{
	memcpy(dest->mailbox_guid, src->mailbox_guid,
	       sizeof(dest->mailbox_guid));
	dest->uid_validity = src->uid_validity;
	dest->existence = src->existence;
	dest->last_renamed = src->last_renamed;
	dest->subscribed = src->subscribed;
	dest->last_subscription_change = src->last_subscription_change;
}

struct dsync_mailbox_tree_iter *
dsync_mailbox_tree_iter_init(struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree_iter *iter;

	iter = i_new(struct dsync_mailbox_tree_iter, 1);
	iter->tree = tree;
	iter->name = str_new(default_pool, 128);
	iter->cur = &tree->root;

	tree->iter_count++;
	return iter;
}

static unsigned int node_get_full_name_length(struct dsync_mailbox_node *node)
{
	if (node->parent->parent == NULL)
		return strlen(node->name);
	else {
		return strlen(node->name) + 1 +
			node_get_full_name_length(node->parent);
	}
}

bool dsync_mailbox_tree_iter_next(struct dsync_mailbox_tree_iter *iter,
				  const char **full_name_r,
				  struct dsync_mailbox_node **node_r)
{
	unsigned int len;

	if (iter->cur->first_child != NULL)
		iter->cur = iter->cur->first_child;
	else {
		while (iter->cur->next == NULL) {
			if (iter->cur == &iter->tree->root)
				return FALSE;
			iter->cur = iter->cur->parent;
		}
		iter->cur = iter->cur->next;
		len = iter->cur->parent == &iter->tree->root ? 0 :
			node_get_full_name_length(iter->cur->parent);
		str_truncate(iter->name, len);
	}
	if (str_len(iter->name) > 0)
		str_append_c(iter->name, iter->tree->sep);
	str_append(iter->name, iter->cur->name);
	*full_name_r = str_c(iter->name);
	*node_r = iter->cur;
	return TRUE;
}

void dsync_mailbox_tree_iter_deinit(struct dsync_mailbox_tree_iter **_iter)
{
	struct dsync_mailbox_tree_iter *iter = *_iter;

	*_iter = NULL;

	i_assert(iter->tree->iter_count > 0);
	iter->tree->iter_count--;

	str_free(&iter->name);
	i_free(iter);
}

void dsync_mailbox_tree_build_name128_hash(struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree_iter *iter;
	struct dsync_mailbox_node *node;
	const char *name;
	guid_128_t *sha128;

	i_assert(tree->name128_hash == NULL);

	tree->name128_hash = hash_table_create(default_pool, tree->pool, 0,
					       guid_128_hash, guid_128_cmp);
	iter = dsync_mailbox_tree_iter_init(tree);
	while (dsync_mailbox_tree_iter_next(iter, &name, &node)) {
		sha128 = p_new(tree->pool, guid_128_t, 1);
		mailbox_name_get_sha128(name, *sha128);
		hash_table_insert(tree->name128_hash, *sha128, node);
	}
	dsync_mailbox_tree_iter_deinit(&iter);
}

static const char *
convert_name_to_remote_sep(struct dsync_mailbox_tree *tree, const char *name)
{
	string_t *str = t_str_new(128);
	char alt_char = doveadm_settings->dsync_alt_char[0];

	for (; *name != '\0'; name++) {
		if (*name == tree->sep)
			str_append_c(str, tree->remote_sep);
		else if (*name == tree->remote_sep)
			str_append_c(str, alt_char);
		else
			str_append_c(str, *name);
	}
	return str_c(str);
}

static void
dsync_mailbox_tree_build_name128_remotesep_hash(struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree_iter *iter;
	struct dsync_mailbox_node *node;
	const char *name;
	guid_128_t *sha128;

	i_assert(tree->sep != tree->remote_sep);
	i_assert(tree->name128_remotesep_hash == NULL);

	tree->name128_remotesep_hash =
		hash_table_create(default_pool, tree->pool, 0,
				  guid_128_hash, guid_128_cmp);
	iter = dsync_mailbox_tree_iter_init(tree);
	while (dsync_mailbox_tree_iter_next(iter, &name, &node)) {
		sha128 = p_new(tree->pool, guid_128_t, 1);
		T_BEGIN {
			const char *remote_name =
				convert_name_to_remote_sep(tree, name);
			mailbox_name_get_sha128(remote_name, *sha128);
		} T_END;
		hash_table_insert(tree->name128_remotesep_hash, *sha128, node);
	}
	dsync_mailbox_tree_iter_deinit(&iter);
}

int dsync_mailbox_tree_guid_hash_add(struct dsync_mailbox_tree *tree,
				     struct dsync_mailbox_node *node)
{
	struct dsync_mailbox_node *old_node;

	if (guid_128_is_empty(node->mailbox_guid))
		return 0;

	old_node = hash_table_lookup(tree->guid_hash, node->mailbox_guid);
	if (old_node != NULL) {
		i_error("Duplicate mailbox GUID %s "
			"for mailboxes %s and %s",
			guid_128_to_string(node->mailbox_guid),
			dsync_mailbox_node_get_full_name(tree, old_node),
			dsync_mailbox_node_get_full_name(tree, node));
		return -1;
	}
	hash_table_insert(tree->guid_hash, node->mailbox_guid, node);
	return 0;
}

int dsync_mailbox_tree_build_guid_hash(struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree_iter *iter;
	struct dsync_mailbox_node *node;
	const char *name;
	int ret = 0;

	i_assert(tree->guid_hash == NULL);

	tree->guid_hash = hash_table_create(default_pool, tree->pool, 0,
					    guid_128_hash, guid_128_cmp);
	iter = dsync_mailbox_tree_iter_init(tree);
	while (dsync_mailbox_tree_iter_next(iter, &name, &node))
		(void)dsync_mailbox_tree_guid_hash_add(tree, node);
	dsync_mailbox_tree_iter_deinit(&iter);
	return ret;
}

const struct dsync_mailbox_delete *
dsync_mailbox_tree_get_deletes(struct dsync_mailbox_tree *tree,
			       unsigned int *count_r)
{
	return array_get(&tree->deletes, count_r);
}

struct dsync_mailbox_node *
dsync_mailbox_tree_find_delete(struct dsync_mailbox_tree *tree,
			       const struct dsync_mailbox_delete *del)
{
	struct hash_table *hash;

	i_assert(tree->guid_hash != NULL);
	i_assert(tree->remote_sep != '\0');

	if (del->delete_mailbox) {
		/* find node by GUID */
		return hash_table_lookup(tree->guid_hash, del->guid);
	}

	/* find node by name. this is a bit tricky, since the hierarchy
	   separator may differ from ours. */
	if (tree->sep == tree->remote_sep) {
		if (tree->name128_hash == NULL)
			dsync_mailbox_tree_build_name128_hash(tree);
		hash = tree->name128_hash;
	} else {
		if (tree->name128_remotesep_hash == NULL)
			dsync_mailbox_tree_build_name128_remotesep_hash(tree);
		hash = tree->name128_remotesep_hash;
	}
	return hash_table_lookup(hash, del->guid);
}

void dsync_mailbox_tree_set_remote_sep(struct dsync_mailbox_tree *tree,
				       char remote_sep)
{
	i_assert(tree->remote_sep == '\0');

	tree->remote_sep = remote_sep;
}
